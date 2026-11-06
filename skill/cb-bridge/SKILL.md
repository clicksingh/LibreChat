---
name: cb-bridge
description: Use for staff requests about their physical Windows PC, Desktop, local files, screenshots, installed apps, or saving into approved PC folders through CB Bridge.
user-invocable: false
disable-model-invocation: false
always-apply: false
---

# CB Bridge: the employee's Windows PC

Use this skill for tasks that may need the signed-in employee's actual Windows workstation. This is a centrally deployed reference; it cannot grant permissions or connect a device.

## Identify the workspace before using a tool

- **CB Bridge**: the signed-in employee's physical Windows PC. Desktop, local drives, open windows, installed programs, and the actual screen belong here.
- **AI sandbox**: a separate private server-side execution environment for building documents, running code, and processing attached files. Its terminal, paths, and installed applications are not those of the employee's PC.
- **Files / Project storage**: durable user-authorized files and project material. Listing this storage is not the same as browsing a Windows folder.
- Never substitute a sandbox filesystem result for a physical-PC observation, or assume a file automatically exists in all three locations.

## Choose only real, current tools

- Read the exact tool names and schemas offered **on this model turn**. Bridge tool names may include server-specific suffixes; call only the exact offered name. Do not guess `bash`, `bash_terminal`, `powershell`, tool aliases, or internal server names.
- If Bridge tools are not exposed, say you cannot inspect or control the PC in this turn. Do not infer connection from a past success, displayed hostname, or user assertion. A relevant tool search may be used only when offered.
- Do not send normal staff to configure MCP endpoints, server identifiers, Cloudflare, tokens, or developer switches. Refer unresolved connection issues to IT.

## Read, Edit, PowerShell, and screenshots

- **Read** permits only locally approved reading or directory listing. For 'check my Desktop' or 'look at the file on my PC', first use available Bridge listing/read/search tools and confirmed Windows paths. Do not assume a folder is approved.
- **Edit** is separate from Read. Creating, changing, moving, and deleting files requires the actual Edit authorization for that target. 'Save this to my approved folder' requires an available write tool, an approved destination, and the local permission decision.
- **PowerShell** is a distinct opt-in capability with potentially broader effect than folder-scoped Read/Edit. Do not assume an approved folder authorizes shell execution. Use only the actual exposed PowerShell/process tool, with clear user intent and local approval. Never silently run commands just to inspect if a safer read-only tool is available.
- **Screen**: 'see my screen' requires an actual authorized Bridge screenshot tool. An image returned by that tool depicts the physical workstation, not the sandbox. Inspect returned pixels; if the image is missing or unreadable, do not invent what was shown.
- For many files, prefer offered batch-read/listing tools when their schema and permissions permit. For mixed formats, distinguish a plain text read from a binary document needing supported extraction; do not claim an unsupported parser is installed.

## Permission and lifecycle decisions

- A local permission **denial** is a final boundary for that operation. Say what access was denied, avoid alternate paths/commands to bypass the control, and direct staff to the approved IT permission workflow.
- A timeout, interrupted request, absent tool, and explicit denial are different outcomes. Describe the observed outcome accurately; never claim approval or success without a returned result.
- After a local Read/Edit folder change, a PowerShell toggle, or tool revision, re-evaluate **current exposed capabilities** and the device's actual response. Do not reuse stale authority. An upgraded permission is not proof that a tool call succeeded.
- After disconnect or reconnect, do not assume the previous Bridge tool name, selected device, screen or permission state remains valid. Refresh available tools when possible; otherwise explain that PC access must be restored before proceeding.
- If a tool disappears between planning and execution, stop using the stale name, re-check current tool availability, and offer a safe fallback. Do not route the action into the sandbox or an imagined alias.
- When a tool fails after an edit or PowerShell action, verify the effect before retrying. Never blindly replay a potentially side-effecting call.

## Common staff requests

- **'Check my Desktop'**: list the real Desktop via authorized Bridge directory tools; do not list the sandbox working directory.
- **'Look at the file on my PC'**: locate and read the approved Windows file; say if the file or folder was not available.
- **'See my screen'**: use an authorized screenshot tool and describe the actual returned image; do not claim screen access from a text-only response.
- **'What apps are installed?'**: use a real authorized inventory capability, or separately approved PowerShell if available. Probe existing applications before suggesting installs.
- **'Save this to my approved folder'**: confirm the target path and Edit access and report the actual write result; do not confuse a sandbox download with a PC save.
- **'Use my computer'**: identify the intended PC task; use only currently exposed Bridge capabilities. General graphical click/type control is not available through this skill. CUA is out of scope.

Keep explanations staff-friendly: say 'CB Bridge' or 'your Windows PC', not internal MCP server names.
