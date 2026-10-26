# AI usage log (Assignment 2)

AI tool: Claude (Anthropic), used through the Claude app.
The work was done in small steps, one prompt per step. Each entry lists my
prompt word for word, what the AI produced (with the commits), and what I
checked myself.

---

## Step 0: planning

**My prompts:**
1. (Attached the A2 PDF) "okay so i got a assignment 2 on continuation of this with same policy ... You may use AI as you did last time. But you must give credit to it and all the details, like your prompt, etc. ..."
2. Answer to the AI's question on how to build it: "see we have to do it in parts not in single prompt keep steps as small as possible prompts too do not make any assumptions"

**AI output:** a 12-step plan mapping every requirement in the A2 PDF to a step. No code.

---

## Step 1: start A2 from A1 and fix the concurrency bugs

**My prompts:**
1. "have you followed the assignment pdf if so then continue"
2. "no keep pushing with maximum commits for it to be as detailed as i want"

**AI output:** branch `a2` created from my A1 `main`, then:
- `server: add a write lock per client socket`
- `server: send DOWNLOAD_OK header and file bytes under one lock`
- `server: send SEND_INCOMING header and bytes under one lock`
- `server: forget a socket's write lock when the client disconnects`
- `server: mark the user offline before replying LOGOUT_OK`

The write-lock bug was found while preparing the A1 demo (4 clients sending
8 MB files to one user at once: only 1 of 4 arrived intact). The logout bug
showed up as a rare failure of the "allusers lists charlie as offline" test.

**What I checked:** `python tests/test_protocol.py` passes (40 runs in a row).
