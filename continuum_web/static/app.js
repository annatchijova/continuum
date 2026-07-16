const $ = (id) => document.getElementById(id);
const categories = { legal: "Legal", financial: "Financial", medical: "Health", identity: "Identity", real_estate: "Home", subscription: "Accounts", professional: "Knowledge", media: "Media", personal: "Personal", credential: "Access", unknown: "Unsorted" };

async function api(path, payload = {}) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Something went wrong.");
  return body;
}
function toast(message, error = false) { const el = $("toast"); el.textContent = message; el.className = `toast show ${error ? "error" : ""}`; setTimeout(() => el.className = "toast", 4200); }
function renderAnswer(container, result) {
  container.replaceChildren();
  const answer = document.createElement("p"); answer.textContent = result.answer; container.append(answer);
  if (result.sources.length) {
    const label = document.createElement("div"); label.className = "source-label"; label.textContent = "SOURCES FOUND";
    const list = document.createElement("ul");
    result.sources.forEach((source) => { const item = document.createElement("li"); const badge = document.createElement("span"); badge.textContent = categories[source.category] || source.category; item.append(badge, document.createTextNode(source.artifact ? source.artifact.split("/").pop() : source.excerpt)); list.append(item); });
    container.append(label, list);
  }
  if (result.narration) {
    const narration = document.createElement("p"); narration.className = "narration";
    const label = document.createElement("b"); label.textContent = "OPTIONAL CHATGPT NARRATION — NOT A SOURCE";
    narration.append(label, document.createElement("br"), document.createTextNode(result.narration)); container.append(narration);
  }
}
function showStudio(data) {
  $("onboarding").hidden = true; $("studio").hidden = false; $("lockButton").hidden = false;
  $("ownerName").textContent = (data.owner_id || "there").split(" ")[0];
  $("memoryCount").textContent = data.total_artifacts;
  const mapped = Object.entries(data.by_category || {}).filter(([, count]) => count > 0);
  $("categoryCount").textContent = mapped.length;
  $("auditCount").textContent = data.audit_events;
  $("integrityText").textContent = data.integrity ? (data.hmac_checked ? "HMAC verified" : "hash-only") : "needs attention";
  $("integrityDot").className = `integrity-dot ${data.integrity ? (data.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`;
  $("securityNote").hidden = data.database_encrypted;
  $("securityNote").textContent = data.database_encrypted ? "" : "Memory database encryption is not enabled for this existing vault. Run legacy encrypt-db before relying on at-rest confidentiality.";
  const heirView = data.role === "heir"; $("captureCard").hidden = heirView;
  $("subheading").textContent = heirView ? "You have read-only access to the verified legacy." : "Your private memory is clear, connected and ready when it matters.";
  $("navStatus").textContent = `${data.total_artifacts} protected memories`;
  $("mapLabel").textContent = mapped.length ? `${mapped.length} areas of life` : "No memories yet";
  $("categoryList").innerHTML = mapped.length ? mapped.map(([key, value]) => `<div class="category-row"><span>${categories[key] || key}</span><div><i style="width:${Math.min(100, 18 + value * 20)}%"></i></div><strong>${value}</strong></div>`).join("") : '<div class="blank-map">Your first captured memory will begin the map.</div>';
}

$("demoButton").addEventListener("click", async () => { try { $("demoButton").disabled = true; $("demoButton").textContent = "Preparing your demo…"; const data = await api("/api/demo"); showStudio(data); toast("Demo workspace is ready. Try asking about the apartment deed."); $("studio").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } finally { $("demoButton").disabled = false; $("demoButton").innerHTML = "Explore a safe demo <span>→</span>"; } });
$("setupButton").addEventListener("click", () => $("onboarding").scrollIntoView({ behavior: "smooth", block: "center" }));
$("workspaceForm").addEventListener("submit", async (event) => { event.preventDefault(); try { const data = await api("/api/create", { owner_id: $("owner").value, passphrase: $("passphrase").value }); showStudio(data); toast("Your protected workspace is open."); } catch (e) { $("formNote").textContent = e.message; } });
$("unlockButton").addEventListener("click", async () => { try { const data = await api("/api/unlock", { owner_id: $("owner").value, passphrase: $("passphrase").value }); showStudio(data); toast("Your workspace is unlocked."); } catch (e) { $("formNote").textContent = e.message; } });
$("heirButton").addEventListener("click", async () => { try { const data = await api("/api/unlock-heir", { heir_id: $("owner").value, passphrase: $("passphrase").value, heir_key: $("heirKey").value }); showStudio(data); toast("Heir workspace opened in read-only mode."); } catch (e) { $("formNote").textContent = e.message; } });
$("memoryFile").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file) return; if (file.size > 65536) { $("captureNote").textContent = "Choose a text file smaller than 64 KiB."; event.target.value = ""; return; } try { $("memoryBody").value = await file.text(); if (!$("memoryTitle").value) $("memoryTitle").value = file.name.replace(/\.[^.]+$/, ""); $("captureNote").textContent = `${file.name} loaded locally. Review before protecting it.`; } catch (_) { $("captureNote").textContent = "That file could not be read as text."; } });
$("captureForm").addEventListener("submit", async (event) => { event.preventDefault(); try { const selectedFile = $("memoryFile").files[0]; const result = await api("/api/capture", { title: $("memoryTitle").value, body: $("memoryBody").value, filename: selectedFile ? selectedFile.name : null, tags: $("memoryTags").value.split(",").map(v => v.trim()).filter(Boolean) }); showStudio(result.dashboard); $("captureNote").textContent = `Protected as ${categories[result.record.category] || result.record.category}.`; event.target.reset(); toast("Memory protected and added to the audit history."); } catch (e) { $("captureNote").textContent = e.message; } });
$("guideButton").addEventListener("click", async () => { try { const result = await api("/api/heir-guide"); $("guideContent").textContent = result.guide; $("guideCard").hidden = false; $("guideCard").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } });
$("verifyButton").addEventListener("click", async () => { try { const result = await api("/api/integrity"); $("integrityText").textContent = result.valid ? (result.audit.hmac_checked ? "HMAC verified" : "hash-only") : "needs attention"; $("integrityDot").className = `integrity-dot ${result.valid ? (result.audit.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`; const state = result.audit.hmac_checked ? "HMAC-protected" : "hash-only"; toast(result.valid ? `${state}: audit and ${result.memory.checked} memory records verified.` : "Integrity needs attention.", !result.valid); } catch (e) { toast(e.message, true); } });
$("closeGuide").addEventListener("click", () => $("guideCard").hidden = true);
$("askForm").addEventListener("submit", async (event) => { event.preventDefault(); const answer = $("answer"); try { answer.className = "answer loading"; answer.textContent = "Finding the relevant thread…"; const result = await api("/api/ask", { question: $("question").value, allow_narration: $("narrationConsent").checked }); answer.className = "answer"; renderAnswer(answer, result); if (result.narration_error) toast(`${result.narration_error} The deterministic result remains unchanged.`, true); } catch (e) { answer.className = "answer"; answer.textContent = e.message; } });
$("lockButton").addEventListener("click", async () => { await api("/api/lock"); $("studio").hidden = true; $("onboarding").hidden = false; $("lockButton").hidden = true; $("navStatus").textContent = "Protected local workspace"; $("passphrase").value = ""; toast("Workspace locked. Your passphrase is cleared from this browser."); window.scrollTo({ top: 0, behavior: "smooth" }); });
