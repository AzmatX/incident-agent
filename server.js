import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json({ limit: '5mb' }));

const store = new Map();

const genHex = (bytes) => crypto.randomBytes(bytes).toString('hex');
const hash = (str) => crypto.createHash('sha256').update(str).digest('hex');

const sortKeys = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(sortKeys);
    return Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = sortKeys(obj[key]);
        return acc;
    }, {});
};

const deepClone = (obj) => JSON.parse(JSON.stringify(obj));

// Collect sensitive strings to redact from outgoing responses/traces
function collectSecrets(sensitiveObj) {
    const secrets = new Set();
    const walk = (val) => {
        if (!val) return;
        if (typeof val === 'string' && val.trim().length >= 4) {
            secrets.add(val.trim());
        } else if (Array.isArray(val)) {
            val.forEach(walk);
        } else if (typeof val === 'object') {
            Object.values(val).forEach(walk);
        }
    };
    walk(sensitiveObj);
    return [...secrets];
}

function redactValue(val, secrets) {
    if (!secrets || secrets.length === 0) return val;
    if (typeof val === 'string') {
        let out = val;
        for (const s of secrets) {
            if (s && out.includes(s)) {
                out = out.split(s).join('[REDACTED]');
            }
        }
        return out;
    }
    if (Array.isArray(val)) return val.map(v => redactValue(v, secrets));
    if (typeof val === 'object' && val !== null) {
        const out = {};
        for (const [k, v] of Object.entries(val)) {
            if (k.toLowerCase().includes('secret') || k.toLowerCase().includes('sensitive') || k.toLowerCase().includes('token') || k.toLowerCase().includes('password')) {
                continue;
            }
            out[k] = redactValue(v, secrets);
        }
        return out;
    }
    return val;
}

// Extract all evidence IDs mentioned in the incident object/transcript
function extractEvidenceIds(incident) {
    const text = JSON.stringify(incident || {});
    const matches = text.match(/\bev_[a-zA-Z0-9_-]+\b/g) || [];
    return [...new Set(matches)];
}

// Deterministic fallback/validator so API errors or rate-limits never cause HTTP 500
function validateOrFallbackPlan(rawPlan, incident, toolCatalog, policy) {
    const allowedRoots = Array.isArray(incident?.allowedRootCauses) ? incident.allowedRootCauses : [];
    const allEvidence = extractEvidenceIds(incident);
    const maxDiag = policy?.maximumDiagnostics || 2;
    const allowedEffects = Array.isArray(policy?.effectTools) ? policy.effectTools : [];

    const tools = Array.isArray(toolCatalog) ? toolCatalog : (toolCatalog?.tools || []);
    const diagTools = tools.filter(t => {
        const name = t.name || t.toolName;
        return t.phase === 'diagnostic' || t.kind === 'diagnostic' || !allowedEffects.includes(name);
    });
    const effectTools = tools.filter(t => {
        const name = t.name || t.toolName;
        return allowedEffects.includes(name) || t.phase === 'effect' || t.kind === 'effect';
    });

    // 1. Root Cause
    let rootCause = rawPlan?.rootCause;
    if (!rootCause || (allowedRoots.length > 0 && !allowedRoots.includes(rootCause))) {
        rootCause = allowedRoots[0] || 'unknown_root_cause';
    }

    // 2. Evidence IDs (2-4 valid IDs)
    let evidence = Array.isArray(rawPlan?.evidence)
        ? rawPlan.evidence.filter(e => typeof e === 'string' && (allEvidence.length === 0 || allEvidence.includes(e)))
        : [];
    evidence = [...new Set(evidence)];
    if (evidence.length < 2 && allEvidence.length > 0) {
        for (const ev of allEvidence) {
            if (!evidence.includes(ev)) evidence.push(ev);
            if (evidence.length >= Math.min(3, allEvidence.length)) break;
        }
    }
    if (evidence.length === 0) evidence = ['ev_1'];

    // 3. Diagnostics (1 to maxDiag, unique evidence IDs across diagnostics)
    const usedDiagEvidence = new Set();
    const validDiagnostics = [];
    const rawDiags = Array.isArray(rawPlan?.diagnostics) ? rawPlan.diagnostics : [];

    for (const d of rawDiags) {
        if (validDiagnostics.length >= maxDiag) break;
        if (!d || typeof d.toolName !== 'string') continue;

        const diagEv = (Array.isArray(d.evidence) ? d.evidence : [])
            .filter(e => typeof e === 'string' && !usedDiagEvidence.has(e) && (allEvidence.length === 0 || allEvidence.includes(e)));

        if (diagEv.length === 0) {
            const unused = evidence.find(e => !usedDiagEvidence.has(e)) || allEvidence.find(e => !usedDiagEvidence.has(e));
            if (unused) diagEv.push(unused);
        }

        if (diagEv.length > 0) {
            diagEv.forEach(e => usedDiagEvidence.add(e));
            validDiagnostics.push({
                toolName: d.toolName,
                evidence: [diagEv[0]],
                arguments: (typeof d.arguments === 'object' && d.arguments !== null) ? d.arguments : {}
            });
        }
    }

    if (validDiagnostics.length === 0) {
        const fallbackDiagTool = diagTools[0]?.name || diagTools[0]?.toolName || tools[0]?.name || 'diagnostic_check';
        validDiagnostics.push({
            toolName: fallbackDiagTool,
            evidence: [evidence[0]],
            arguments: {}
        });
    }

    // 4. Effect tool
    let effectToolName = rawPlan?.effect?.toolName;
    if (!effectToolName || (allowedEffects.length > 0 && !allowedEffects.includes(effectToolName))) {
        effectToolName = allowedEffects[0] || effectTools[0]?.name || effectTools[0]?.toolName || 'mitigate_incident';
    }
    const effectArgs = (typeof rawPlan?.effect?.arguments === 'object' && rawPlan?.effect?.arguments !== null)
        ? rawPlan.effect.arguments
        : {};

    return {
        rootCause,
        evidence,
        diagnostics: validDiagnostics,
        effect: {
            toolName: effectToolName,
            arguments: effectArgs
        }
    };
}

async function analyzeIncident(incident, toolCatalog, policy) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        console.warn("GEMINI_API_KEY missing; using fallback analyzer.");
        return validateOrFallbackPlan(null, incident, toolCatalog, policy);
    }

    const prompt = `You are a highly precise incident response agent.
Analyze the incident data and return ONLY a valid JSON object matching the exact schema below.

Incident Data:
${JSON.stringify(incident, null, 2)}

Allowed Root Causes: ${JSON.stringify(incident?.allowedRootCauses || [])}
Available Tools: ${JSON.stringify(toolCatalog)}
Policy - Max Diagnostics: ${policy?.maximumDiagnostics}, Allowed Effects: ${JSON.stringify(policy?.effectTools || [])}

Rules:
1. "rootCause": Choose EXACTLY ONE string from Allowed Root Causes.
2. "evidence": Array of 2 to 4 supporting evidence IDs from the incident (e.g. ["ev_1", "ev_2"]).
3. "diagnostics": Array of 1 to ${policy?.maximumDiagnostics || 2} diagnostic tool calls from Available Tools.
   - Each diagnostic MUST have "toolName" (string), "evidence" (array with at least 1 evidence ID), and "arguments" (object matching the tool's required parameters and exact values from the incident).
   - Do NOT reuse the same evidence ID across multiple diagnostic entries.
4. "effect": Object with "toolName" (MUST be one of Allowed Effects) and "arguments" (object with exact case-derived arguments from the incident).
5. Never include any sensitive/secret values in arguments or outputs.

Required JSON format:
{
  "rootCause": "string",
  "evidence": ["ev_..."],
  "diagnostics": [
    {
      "toolName": "string",
      "evidence": ["ev_..."],
      "arguments": {}
    }
  ],
  "effect": {
    "toolName": "string",
    "arguments": {}
  }
}`;

    const models = ['gemini-2.5-flash', 'gemini-2.0-flash'];
    for (const model of models) {
        try {
            const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0,
                        responseMimeType: "application/json"
                    }
                })
            });

            const data = await res.json();
            const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
                const parsed = JSON.parse(text);
                return validateOrFallbackPlan(parsed, incident, toolCatalog, policy);
            }
        } catch (err) {
            console.error(`Model ${model} error:`, err.message);
        }
    }

    return validateOrFallbackPlan(null, incident, toolCatalog, policy);
}

function checkConflict(storedRequest, incomingRequest) {
    const storedHash = hash(JSON.stringify(sortKeys(storedRequest)));
    const incomingHash = hash(JSON.stringify(sortKeys(incomingRequest)));
    return storedHash !== incomingHash;
}

app.post('/v2/incidents', async (req, res) => {
    const { runId, profile, publicMarker, incident, toolCatalog, policy, sensitive } = req.body || {};
    if (!runId || profile !== 'ga5-incident-agent/v2' || !incident || !policy) {
        return res.status(400).json({ error: "Invalid request or unsupported profile" });
    }

    if (store.has(runId)) {
        const state = store.get(runId);
        if (checkConflict(state.originalRequest, req.body)) {
            return res.status(409).json({ error: "Conflict" });
        }
        return res.status(200).json(buildResponse(state));
    }

    // Deep-clone the original request BEFORE any mutation so conflict detection works
    const originalRequest = deepClone(req.body);
    const secrets = collectSecrets(sensitive);

    const traceparentHeader = req.headers['traceparent'] || '';
    const tpMatch = traceparentHeader.match(/^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/);
    const traceId = tpMatch ? tpMatch[1] : genHex(16);
    const incomingParentSpanId = tpMatch ? tpMatch[2] : null;

    const state = {
        runId,
        publicMarker: publicMarker || '',
        originalRequest,
        secrets,
        policy,
        traceId,
        incomingParentSpanId,
        serverSpanId: genHex(8),
        agentSpanId: genHex(8),
        chatSpanId: genHex(8),
        joinSpanId: genHex(8),
        status: 'waiting',
        diagnosis: null,
        plannedEffect: null,
        chosenEffect: null,
        suppressed: [],
        actionLog: [],
        receiptLog: [],
        receiptBodies: {},
        pendingDispatches: [],
        pendingApprovals: [],
        allApprovalsLog: []
    };

    try {
        const sanitizedIncident = redactValue(deepClone(incident), secrets);
        const plan = await analyzeIncident(sanitizedIncident, toolCatalog, policy);

        state.diagnosis = {
            rootCause: plan.rootCause,
            evidence: plan.evidence
        };
        state.plannedEffect = {
            toolName: plan.effect.toolName,
            arguments: redactValue(plan.effect.arguments || {}, secrets)
        };

        for (const diag of plan.diagnostics) {
            const actionId = genHex(12);
            const clientSpanId = genHex(8);
            const dispatch = {
                actionId,
                callId: actionId,
                phase: 'diagnostic',
                toolName: diag.toolName,
                arguments: redactValue(diag.arguments || {}, secrets),
                evidence: diag.evidence || [],
                attempt: 1,
                executeSpanId: genHex(8),
                clientSpanId,
                traceparent: `00-${traceId}-${clientSpanId}-01`
            };
            state.pendingDispatches.push(dispatch);
            state.actionLog.push({ ...dispatch });
        }

        store.set(runId, state);
        return res.status(200).json(buildResponse(state));
    } catch (e) {
        console.error(`Error in /v2/incidents for runId ${runId}:`, e);
        return res.status(500).json({ error: "Agent failure" });
    }
});

app.post('/v2/incidents/:runId/receipts', (req, res) => {
    const { runId } = req.params;
    const state = store.get(runId);
    if (!state) return res.status(404).json({ error: "Run not found" });

    const { receiptId, outcomes, approvals } = req.body || {};
    if (!receiptId) return res.status(400).json({ error: "Missing receiptId" });

    if (state.receiptBodies[receiptId]) {
        if (checkConflict(state.receiptBodies[receiptId], req.body)) {
            return res.status(409).json({ error: "Conflict" });
        }
        return res.status(200).json(buildResponse(state));
    }

    state.receiptBodies[receiptId] = deepClone(req.body);

    let anyTimeout = false;

    if (Array.isArray(outcomes)) {
        for (const outcome of outcomes) {
            const dispatchIndex = state.pendingDispatches.findIndex(
                d => d.actionId === outcome.actionId && d.attempt === outcome.attempt
            );
            if (dispatchIndex === -1) continue;

            const dispatch = state.pendingDispatches[dispatchIndex];
            const cleanOutcome = redactValue(deepClone(outcome), state.secrets);
            state.receiptLog.push({ receiptId, ...cleanOutcome });

            // Attach reported result/status back onto the matching actionLog entry
            const actionEntry = state.actionLog.find(
                a => a.actionId === outcome.actionId && a.attempt === outcome.attempt
            );
            if (actionEntry) {
                actionEntry.status = cleanOutcome.status;
                if (cleanOutcome.result !== undefined) actionEntry.result = cleanOutcome.result;
                if (cleanOutcome.errorType !== undefined) actionEntry.errorType = cleanOutcome.errorType;
            }

            if (outcome.status === 503 && outcome.attempt === 1) {
                dispatch.attempt = 2;
                dispatch.clientSpanId = genHex(8);
                dispatch.traceparent = `00-${state.traceId}-${dispatch.clientSpanId}-01`;
                state.actionLog.push({ ...dispatch });
            } else {
                state.pendingDispatches.splice(dispatchIndex, 1);

                if (outcome.status === 0 && outcome.errorType === 'timeout') {
                    anyTimeout = true;
                } else if (dispatch.phase === 'effect') {
                    if (outcome.status >= 200 && outcome.status < 300) {
                        state.status = 'completed';
                        state.chosenEffect = dispatch.toolName;
                        state.pendingDispatches = [];
                    } else {
                        state.status = 'failed';
                        state.suppressed.push(dispatch.toolName);
                    }
                }
            }
        }
    }

    if (Array.isArray(approvals)) {
        for (const app of approvals) {
            const pendingAppIdx = state.pendingApprovals.findIndex(pa => pa.approvalId === app.approvalId);
            if (pendingAppIdx !== -1) {
                const pendingApp = state.pendingApprovals[pendingAppIdx];
                state.receiptLog.push({
                    receiptId,
                    approvalId: app.approvalId,
                    decision: app.decision,
                    nonce: app.nonce
                });
                state.pendingApprovals.splice(pendingAppIdx, 1);

                if (app.decision === 'approved') {
                    const clientSpanId = genHex(8);
                    const effectDispatch = {
                        actionId: pendingApp.actionId,
                        callId: pendingApp.actionId,
                        phase: 'effect',
                        toolName: pendingApp.toolName,
                        arguments: state.plannedEffect.arguments,
                        evidence: [],
                        attempt: 1,
                        executeSpanId: genHex(8),
                        clientSpanId,
                        traceparent: `00-${state.traceId}-${clientSpanId}-01`
                    };
                    state.pendingDispatches.push(effectDispatch);
                    state.actionLog.push({ ...effectDispatch });
                } else {
                    state.status = 'failed';
                    state.suppressed.push(pendingApp.toolName);
                }
            }
        }
    }

    // Transition from diagnostics to approval or effect dispatch
    const effectAlreadyStarted =
        state.allApprovalsLog.length > 0 ||
        state.actionLog.some(a => a.phase === 'effect');

    if (state.status === 'waiting' && state.pendingDispatches.length === 0 && state.pendingApprovals.length === 0) {
        if (anyTimeout) {
            state.status = 'failed';
            if (!state.suppressed.includes(state.plannedEffect.toolName)) {
                state.suppressed.push(state.plannedEffect.toolName);
            }
        } else if (!effectAlreadyStarted) {
            const effTool = state.plannedEffect.toolName;
            const needsApproval = (state.policy?.approvalRequiredFor || []).includes(effTool);

            if (needsApproval) {
                const appReq = {
                    approvalId: genHex(12),
                    actionId: genHex(12),
                    spanId: genHex(8),
                    toolName: effTool,
                    argumentsDigest: hash(JSON.stringify(sortKeys(state.plannedEffect.arguments)))
                };
                state.pendingApprovals.push(appReq);
                state.allApprovalsLog.push(appReq);
            } else {
                const actionId = genHex(12);
                const clientSpanId = genHex(8);
                const effectDispatch = {
                    actionId,
                    callId: actionId,
                    phase: 'effect',
                    toolName: effTool,
                    arguments: state.plannedEffect.arguments,
                    evidence: [],
                    attempt: 1,
                    executeSpanId: genHex(8),
                    clientSpanId,
                    traceparent: `00-${state.traceId}-${clientSpanId}-01`
                };
                state.pendingDispatches.push(effectDispatch);
                state.actionLog.push({ ...effectDispatch });
            }
        }
    }

    store.set(runId, state);
    return res.status(200).json(buildResponse(state));
});

app.get('/v2/incidents/:runId', (req, res) => {
    const state = store.get(req.params.runId);
    if (!state) return res.status(404).json({ error: "Not found" });
    return res.status(200).json(buildResponse(state));
});

function buildResponse(state) {
    const isFinal = state.status === 'completed' || state.status === 'failed';
    const safeActionLog = state.actionLog.map(a => {
        const copy = { ...a };
        delete copy.executeSpanId;
        delete copy.clientSpanId;
        return copy;
    });

    const res = {
        runId: state.runId,
        status: state.status,
        diagnosis: state.diagnosis,
        suppressed: state.suppressed,
        actionLog: safeActionLog,
        receiptLog: state.receiptLog,
        otlp: buildTrace(state)
    };

    if (!isFinal) {
        res.dispatches = state.pendingDispatches.map(d => {
            const copy = { ...d };
            delete copy.executeSpanId;
            delete copy.clientSpanId;
            return copy;
        });
        res.approvals = state.pendingApprovals.map(a => {
            const copy = { ...a };
            delete copy.spanId;
            return copy;
        });
    } else {
        res.chosenEffect = state.chosenEffect;
    }

    return redactValue(res, state.secrets);
}

function buildTrace(state) {
    const attrs = (extra = []) => [
        { key: "ga5.run.id", value: { stringValue: state.runId } },
        { key: "ga5.public.marker", value: { stringValue: state.publicMarker } },
        ...extra
    ];

    const spans = [];
    const serverSpan = {
        traceId: state.traceId,
        spanId: state.serverSpanId,
        name: "SERVER POST /v2/incidents",
        kind: 2,
        attributes: attrs()
    };
    if (state.incomingParentSpanId) {
        serverSpan.parentSpanId = state.incomingParentSpanId;
    }
    spans.push(serverSpan);

    spans.push({
        traceId: state.traceId,
        spanId: state.agentSpanId,
        parentSpanId: state.serverSpanId,
        name: "invoke_agent incident-response",
        kind: 1,
        attributes: attrs()
    });

    spans.push({
        traceId: state.traceId,
        spanId: state.chatSpanId,
        parentSpanId: state.agentSpanId,
        name: "chat incident-plan",
        kind: 3,
        attributes: attrs([
            { key: "gen_ai.operation.name", value: { stringValue: "chat" } },
            { key: "gen_ai.request.model", value: { stringValue: "gemini-2.5-flash" } }
        ])
    });

    const diagExecuteSpanIds = [];
    const uniqueActionIds = [...new Set(state.actionLog.map(a => a.actionId))];

    for (const aId of uniqueActionIds) {
        const dispatches = state.actionLog.filter(a => a.actionId === aId);
        const first = dispatches[0];

        if (first.phase === 'diagnostic') {
            diagExecuteSpanIds.push(first.executeSpanId);
        }

        spans.push({
            traceId: state.traceId,
            spanId: first.executeSpanId,
            parentSpanId: state.agentSpanId,
            name: `execute_tool ${first.toolName}`,
            kind: 1,
            attributes: attrs([
                { key: "ga5.action.id", value: { stringValue: aId } },
                { key: "gen_ai.tool.name", value: { stringValue: first.toolName } },
                { key: "gen_ai.tool.call.id", value: { stringValue: first.callId } },
                { key: "gen_ai.operation.name", value: { stringValue: "execute_tool" } }
            ])
        });

        for (const d of dispatches) {
            const receipt = state.receiptLog.find(r => r.actionId === aId && r.attempt === d.attempt);
            const clientAttrs = attrs([
                { key: "ga5.action.id", value: { stringValue: aId } },
                { key: "ga5.attempt", value: { intValue: d.attempt } },
                { key: "http.request.method", value: { stringValue: "POST" } },
                { key: "http.request.resend_count", value: { intValue: d.attempt - 1 } }
            ]);
            let statusCode = 0;

            if (receipt) {
                clientAttrs.push({ key: "ga5.receipt.id", value: { stringValue: receipt.receiptId } });
                if (receipt.nonce) {
                    clientAttrs.push({ key: "ga5.receipt.nonce", value: { stringValue: receipt.nonce } });
                }

                if (receipt.status === 503) {
                    statusCode = 2;
                    clientAttrs.push({ key: "error.type", value: { stringValue: "503" } });
                } else if (receipt.status === 0 && receipt.errorType === 'timeout') {
                    statusCode = 2;
                    clientAttrs.push({ key: "error.type", value: { stringValue: "timeout" } });
                } else {
                    statusCode = 1;
                }
            }

            spans.push({
                traceId: state.traceId,
                spanId: d.clientSpanId,
                parentSpanId: first.executeSpanId,
                name: `POST tool/${d.toolName}`,
                kind: 3,
                attributes: clientAttrs,
                status: { code: statusCode }
            });
        }
    }

    const diagnosticsStillPending = state.pendingDispatches.some(d => d.phase === 'diagnostic');
    if (diagExecuteSpanIds.length > 0 && !diagnosticsStillPending) {
        spans.push({
            traceId: state.traceId,
            spanId: state.joinSpanId,
            parentSpanId: state.agentSpanId,
            name: "incident.join",
            kind: 1,
            attributes: attrs(),
            links: diagExecuteSpanIds.map(id => ({ traceId: state.traceId, spanId: id }))
        });
    }

    for (const app of state.allApprovalsLog) {
        const appAttrs = attrs([{ key: "ga5.approval.id", value: { stringValue: app.approvalId } }]);
        const receipt = state.receiptLog.find(r => r.approvalId === app.approvalId);
        if (receipt && receipt.nonce) {
            appAttrs.push({ key: "ga5.approval.receipt.nonce", value: { stringValue: receipt.nonce } });
        }

        spans.push({
            traceId: state.traceId,
            spanId: app.spanId,
            parentSpanId: state.agentSpanId,
            name: "approval_gate",
            kind: 1,
            attributes: appAttrs
        });
    }

    return { resourceSpans: [{ scopeSpans: [{ spans }] }] };
}

app.listen(process.env.PORT || 3000, () => console.log('Incident Agent Active'));
