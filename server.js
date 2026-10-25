import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json({ limit: '5mb' }));

// In-memory store for the grader's testing window
const store = new Map();

// Helper: Generate deterministic/random lowercase hex
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

// Helper: Call Gemini API for root cause analysis
async function analyzeIncident(incident, toolCatalog, policy) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        console.error("ERROR: GEMINI_API_KEY is missing in Render Environment Variables!");
        throw new Error("GEMINI_API_KEY is required");
    }

    const prompt = `You are a highly precise incident response agent.
Incident Transcript:
${incident.transcript}

Allowed Root Causes: ${JSON.stringify(incident.allowedRootCauses)}
Available Tools: ${JSON.stringify(toolCatalog)}
Policy - Max Diagnostics: ${policy.maximumDiagnostics}, Allowed Effects: ${JSON.stringify(policy.effectTools)}

Choose ONE root cause from the allowed list. Cite 2-4 evidence IDs (e.g. "ev_123").
Choose 1 to ${policy.maximumDiagnostics} diagnostic tools to confirm it. Each diagnostic MUST cite at least one evidence ID. No duplicate evidence IDs across diagnostics.
Choose exactly ONE effect tool from the allowed effects to resolve the incident.`;

    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { 
                response_mime_type: "application/json",
                response_schema: {
                    type: "OBJECT",
                    properties: {
                        rootCause: { type: "STRING" },
                        evidence: { type: "ARRAY", items: { type: "STRING" } },
                        diagnostics: {
                            type: "ARRAY",
                            items: {
                                type: "OBJECT",
                                properties: {
                                    toolName: { type: "STRING" },
                                    evidence: { type: "ARRAY", items: { type: "STRING" } },
                                    arguments: { type: "OBJECT" }
                                },
                                required: ["toolName", "evidence", "arguments"]
                            }
                        },
                        effect: {
                            type: "OBJECT",
                            properties: {
                                toolName: { type: "STRING" },
                                arguments: { type: "OBJECT" }
                            },
                            required: ["toolName", "arguments"]
                        }
                    },
                    required: ["rootCause", "evidence", "diagnostics", "effect"]
                }
            }
        })
    });

    const data = await res.json();
    if (!data.candidates || data.candidates.length === 0) {
        console.error("Gemini API Error Payload:", JSON.stringify(data, null, 2));
        throw new Error("Gemini returned an error instead of valid response");
    }

    return JSON.parse(data.candidates[0].content.parts[0].text);
}

// Ensure replay idempotency & conflict handling
function checkConflict(storedRequest, incomingRequest) {
    const storedHash = hash(JSON.stringify(sortKeys(storedRequest)));
    const incomingHash = hash(JSON.stringify(sortKeys(incomingRequest)));
    return storedHash !== incomingHash;
}

// --- Endpoint: Initialize Run ---
app.post('/v2/incidents', async (req, res) => {
    const { runId, profile, publicMarker, incident, toolCatalog, policy } = req.body;
    if (profile !== 'ga5-incident-agent/v2') return res.status(400).json({ error: "Unsupported profile" });

    // Handle replay / conflict
    if (store.has(runId)) {
        const state = store.get(runId);
        if (checkConflict(state.originalRequest, req.body)) return res.status(409).json({ error: "Conflict" });
        return res.json(buildResponse(state));
    }

    // Parse Trace Context
    const traceparentHeader = req.headers['traceparent'] || '';
    const tpMatch = traceparentHeader.match(/^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/);
    const traceId = tpMatch ? tpMatch[1] : genHex(16);
    const incomingParentSpanId = tpMatch ? tpMatch[2] : null;

    // Secure base state (Drop sensitive fields entirely)
    const safeRequest = { ...req.body };
    delete safeRequest.sensitive;
    delete safeRequest.incident.transcript;

    const state = {
        runId, publicMarker, originalRequest: req.body, policy,
        traceId, incomingParentSpanId,
        serverSpanId: genHex(8), agentSpanId: genHex(8), chatSpanId: genHex(8), joinSpanId: genHex(8),
        status: 'waiting',
        diagnosis: null,
        plannedEffect: null,
        chosenEffect: null,
        suppressed: [],
        actionLog: [],
        receiptLog: [],
        pendingDispatches: [],
        pendingApprovals: [],
        allApprovalsLog: []
    };

    try {
        const plan = await analyzeIncident(incident, toolCatalog, policy);
        state.diagnosis = { rootCause: plan.rootCause, evidence: plan.evidence };
        state.plannedEffect = plan.effect;

        // Generate Diagnostics Dispatches
        for (const diag of plan.diagnostics) {
            const actionId = genHex(12);
            const dispatch = {
                actionId, callId: actionId, phase: 'diagnostic', toolName: diag.toolName,
                arguments: diag.arguments || {}, evidence: diag.evidence || [], attempt: 1,
                executeSpanId: genHex(8), clientSpanId: genHex(8)
            };
            dispatch.traceparent = `00-${traceId}-${dispatch.clientSpanId}-01`;
            state.pendingDispatches.push(dispatch);
            state.actionLog.push({ ...dispatch });
        }

        store.set(runId, state);
        return res.json(buildResponse(state));
    } catch (e) {
        console.error(`Error in /v2/incidents for runId ${runId}:`, e);
        return res.status(500).json({ error: "Agent failure" });
    }
});

// --- Endpoint: Process Receipts ---
app.post('/v2/incidents/:runId/receipts', (req, res) => {
    const { runId } = req.params;
    const state = store.get(runId);
    if (!state) return res.status(404).json({ error: "Run not found" });

    const { receiptId, outcomes, approvals } = req.body;
    const existingReceipt = state.receiptLog.find(r => r.receiptId === receiptId);
    
    // Check for replay vs conflict
    if (existingReceipt) {
        if (!state.receiptBodies) state.receiptBodies = {};
        if (checkConflict(state.receiptBodies[receiptId], req.body)) return res.status(409).json({ error: "Conflict" });
        return res.json(buildResponse(state));
    }

    if (!state.receiptBodies) state.receiptBodies = {};
    state.receiptBodies[receiptId] = req.body;

    let anyTimeout = false;

    // Process Tool Outcomes
    if (outcomes) {
        for (const outcome of outcomes) {
            const dispatchIndex = state.pendingDispatches.findIndex(d => d.actionId === outcome.actionId && d.attempt === outcome.attempt);
            if (dispatchIndex === -1 && state.actionLog.some(a => a.phase === 'effect' && a.actionId === outcome.actionId)) {
                state.receiptLog.push({ receiptId, ...outcome });
                state.status = 'completed';
                state.chosenEffect = state.plannedEffect.toolName;
                state.pendingDispatches = [];
                continue;
            }
            if (dispatchIndex === -1) continue;

            const dispatch = state.pendingDispatches[dispatchIndex];
            state.receiptLog.push({ receiptId, ...outcome });

            if (outcome.status === 503 && outcome.attempt === 1) {
                dispatch.attempt = 2;
                dispatch.clientSpanId = genHex(8);
                dispatch.traceparent = `00-${state.traceId}-${dispatch.clientSpanId}-01`;
                state.actionLog.push({ ...dispatch });
            } else {
                if (outcome.status === 0 && outcome.errorType === 'timeout') {
                    anyTimeout = true;
                }
                state.pendingDispatches.splice(dispatchIndex, 1);
            }
        }
    }

    // Process Approvals
    if (approvals) {
        for (const app of approvals) {
            const pendingAppIdx = state.pendingApprovals.findIndex(pa => pa.approvalId === app.approvalId);
            if (pendingAppIdx !== -1) {
                const pendingApp = state.pendingApprovals[pendingAppIdx];
                state.receiptLog.push({ receiptId, approvalId: app.approvalId, decision: app.decision, nonce: app.nonce });
                state.pendingApprovals.splice(pendingAppIdx, 1);
                
                if (app.decision === 'approved') {
                    const effectDispatch = {
                        actionId: pendingApp.actionId, callId: genHex(12), phase: 'effect',
                        toolName: pendingApp.toolName, arguments: state.plannedEffect.arguments,
                        evidence: [], attempt: 1, executeSpanId: genHex(8), clientSpanId: genHex(8)
                    };
                    effectDispatch.traceparent = `00-${state.traceId}-${effectDispatch.clientSpanId}-01`;
                    state.pendingDispatches.push(effectDispatch);
                    state.actionLog.push({ ...effectDispatch });
                } else {
                    state.status = 'failed';
                    state.suppressed.push(pendingApp.toolName);
                }
            }
        }
    }

    // State Transitions
    if (state.status === 'waiting' && state.pendingDispatches.length === 0 && state.pendingApprovals.length === 0) {
        if (anyTimeout) {
            state.status = 'failed';
            state.suppressed.push(state.plannedEffect.toolName);
        } else {
            const effTool = state.plannedEffect.toolName;
            const needsApproval = (state.policy.approvalRequiredFor || []).includes(effTool);
            
            if (needsApproval) {
                const appReq = {
                    approvalId: genHex(12), actionId: genHex(12), spanId: genHex(8),
                    toolName: effTool, argumentsDigest: hash(JSON.stringify(sortKeys(state.plannedEffect.arguments)))
                };
                state.pendingApprovals.push(appReq);
                state.allApprovalsLog.push(appReq);
            } else {
                const effectDispatch = {
                    actionId: genHex(12), callId: genHex(12), phase: 'effect',
                    toolName: effTool, arguments: state.plannedEffect.arguments,
                    evidence: [], attempt: 1, executeSpanId: genHex(8), clientSpanId: genHex(8)
                };
                effectDispatch.traceparent = `00-${state.traceId}-${effectDispatch.clientSpanId}-01`;
                state.pendingDispatches.push(effectDispatch);
                state.actionLog.push({ ...effectDispatch });
            }
        }
    }

    store.set(runId, state);
    return res.json(buildResponse(state));
});

// --- Endpoint: Get State ---
app.get('/v2/incidents/:runId', (req, res) => {
    const state = store.get(req.params.runId);
    if (!state) return res.status(404).json({ error: "Not found" });
    return res.json(buildResponse(state));
});

// --- OTLP & Response Builder ---
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

    return res;
}

function buildTrace(state) {
    const attrs = (extra = []) => [
        { key: "ga5.run.id", value: { stringValue: state.runId } },
        { key: "ga5.public.marker", value: { stringValue: state.publicMarker } },
        ...extra
    ];

    const spans = [];
    spans.push({ traceId: state.traceId, spanId: state.serverSpanId, parentSpanId: state.incomingParentSpanId || undefined, name: "SERVER POST /v2/incidents", kind: 2, attributes: attrs() });
    spans.push({ traceId: state.traceId, spanId: state.agentSpanId, parentSpanId: state.serverSpanId, name: "invoke_agent incident-response", kind: 1, attributes: attrs() });
    spans.push({ traceId: state.traceId, spanId: state.chatSpanId, parentSpanId: state.agentSpanId, name: "chat incident-plan", kind: 3, attributes: attrs([
        { key: "gen_ai.operation.name", value: { stringValue: "chat" } },
        { key: "gen_ai.request.model", value: { stringValue: "gemini-1.5-flash" } }
    ])});

    const diagExecuteSpanIds = [];
    const uniqueActionIds = [...new Set(state.actionLog.map(a => a.actionId))];

    for (const aId of uniqueActionIds) {
        const dispatches = state.actionLog.filter(a => a.actionId === aId);
        const first = dispatches[0];
        
        if (first.phase === 'diagnostic') diagExecuteSpanIds.push(first.executeSpanId);
        
        spans.push({
            traceId: state.traceId, spanId: first.executeSpanId, parentSpanId: state.agentSpanId, name: `execute_tool ${first.toolName}`, kind: 1,
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
            let statusCode = 0; // UNSET

            if (receipt) {
                clientAttrs.push({ key: "ga5.receipt.id", value: { stringValue: receipt.receiptId } });
                clientAttrs.push({ key: "ga5.receipt.nonce", value: { stringValue: receipt.nonce } });
                
                if (receipt.status === 503) {
                    statusCode = 2; // ERROR
                    clientAttrs.push({ key: "error.type", value: { stringValue: "503" } });
                } else if (receipt.status === 0 && receipt.errorType === 'timeout') {
                    statusCode = 2; // ERROR
                    clientAttrs.push({ key: "error.type", value: { stringValue: "timeout" } });
                } else {
                    statusCode = 1; // OK
                }
            }

            spans.push({ traceId: state.traceId, spanId: d.clientSpanId, parentSpanId: first.executeSpanId, name: `POST tool/${d.toolName}`, kind: 3, attributes: clientAttrs, status: { code: statusCode } });
        }
    }

    if (diagExecuteSpanIds.length > 0) {
        spans.push({
            traceId: state.traceId, spanId: state.joinSpanId, parentSpanId: state.agentSpanId, name: "incident.join", kind: 1,
            attributes: attrs(), links: diagExecuteSpanIds.map(id => ({ traceId: state.traceId, spanId: id }))
        });
    }

    for (const app of state.allApprovalsLog) {
        const appAttrs = attrs([{ key: "ga5.approval.id", value: { stringValue: app.approvalId } }]);
        const receipt = state.receiptLog.find(r => r.approvalId === app.approvalId);
        if (receipt) appAttrs.push({ key: "ga5.approval.receipt.nonce", value: { stringValue: receipt.nonce } });
        
        spans.push({ traceId: state.traceId, spanId: app.
