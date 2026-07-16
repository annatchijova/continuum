const $ = (id) => document.getElementById(id);
const categories = { legal: "Legal", financial: "Finanzas", medical: "Salud", identity: "Identidad", real_estate: "Hogar", subscription: "Cuentas", professional: "Conocimiento", media: "Medios", personal: "Personal", credential: "Acceso", unknown: "Sin clasificar" };
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (!reducedMotion) {
  const vaultVisual = document.querySelector(".vault-visual");
  if (vaultVisual) vaultVisual.style.transition = "transform 180ms ease-out";
  vaultVisual?.addEventListener("pointermove", (event) => {
    const bounds = vaultVisual.getBoundingClientRect();
    const x = (event.clientX - bounds.left) / bounds.width - .5;
    const y = (event.clientY - bounds.top) / bounds.height - .5;
    vaultVisual.style.transform = `perspective(900px) rotateX(${-y * 3}deg) rotateY(${x * 4}deg)`;
  });
  vaultVisual?.addEventListener("pointerleave", () => { vaultVisual.style.transform = ""; });
}

async function api(path, payload = {}) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Algo salió mal.");
  return body;
}
function toast(message, error = false) { const el = $("toast"); el.textContent = message; el.className = `toast show ${error ? "error" : ""}`; setTimeout(() => el.className = "toast", 4200); }
function renderAnswer(container, result) {
  container.replaceChildren();
  const answer = document.createElement("p"); answer.textContent = result.answer; container.append(answer);
  if (result.sources.length) {
    const label = document.createElement("div"); label.className = "source-label"; label.textContent = "FUENTES ENCONTRADAS";
    const list = document.createElement("ul");
    result.sources.forEach((source) => { const item = document.createElement("li"); const badge = document.createElement("span"); badge.textContent = categories[source.category] || source.category; item.append(badge, document.createTextNode(source.artifact ? source.artifact.split("/").pop() : source.excerpt)); list.append(item); });
    container.append(label, list);
  }
  if (result.narration) {
    const narration = document.createElement("p"); narration.className = "narration";
    const label = document.createElement("b"); label.textContent = "NARRACIÓN OPCIONAL DE CHATGPT — NO ES UNA FUENTE";
    narration.append(label, document.createElement("br"), document.createTextNode(result.narration)); container.append(narration);
  }
  if (result.agent_flow) {
    const flow = document.createElement("p"); flow.className = "narration";
    const label = document.createElement("b"); label.textContent = "FLUJO DE AGENTE VERIFICADO";
    const narrationStates = { not_requested: "no solicitada", skipped_no_evidence: "omitida: no hay evidencia seleccionada por el núcleo", skipped_not_configured: "omitida: no está configurada", completed: "completada", failed: "no disponible" };
    flow.append(label, document.createElement("br"), document.createTextNode(`El retrieval del núcleo se completó con ${result.agent_flow.selected_sources} fuente(s) seleccionada(s). Narración opcional: ${narrationStates[result.agent_flow.narration] || result.agent_flow.narration}.`)); container.append(flow);
  }
}
function showStudio(data) {
  $("onboarding").hidden = true; $("studio").hidden = false; $("lockButton").hidden = false;
  $("ownerName").textContent = (data.owner_id || "ahí").split(" ")[0];
  $("memoryCount").textContent = data.total_artifacts;
  const mapped = Object.entries(data.by_category || {}).filter(([, count]) => count > 0);
  $("categoryCount").textContent = mapped.length;
  $("auditCount").textContent = data.audit_events;
  $("integrityText").textContent = data.integrity ? (data.hmac_checked ? "HMAC verificado" : "sólo hash") : "requiere atención";
  $("integrityDot").className = `integrity-dot ${data.integrity ? (data.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`;
  const securityMessages = [];
  if (!data.database_encrypted) securityMessages.push("El cifrado de la base de memorias no está activo para este vault existente. Ejecutá legacy encrypt-db antes de confiar en la confidencialidad en reposo.");
  if (!data.hmac_checked) securityMessages.push("La auditoría sólo verifica hashes. Configurá LEGACY_HMAC_KEY para resistir reescrituras de la cadena por alguien con acceso de escritura.");
  if (!data.heir_policy_configured) securityMessages.push("No hay una política de acceso para herederos. Cualquiera con la frase secreta del vault puede solicitar la ruta de heredero.");
  $("securityNote").hidden = securityMessages.length === 0;
  $("securityNote").textContent = securityMessages.join(" ");
  const heirView = data.role === "heir"; $("captureCard").hidden = heirView;
  $("subheading").textContent = heirView ? "Tenés acceso de sólo lectura al legado verificado." : "Tu memoria privada está clara, conectada y preparada para cuando importe.";
  $("navStatus").textContent = `${data.total_artifacts} memorias protegidas`;
  $("mapLabel").textContent = mapped.length ? `${mapped.length} áreas de vida` : "Aún no hay memorias";
  $("categoryList").innerHTML = mapped.length ? mapped.map(([key, value]) => `<div class="category-row"><span>${categories[key] || key}</span><div><i style="width:${Math.min(100, 18 + value * 20)}%"></i></div><strong>${value}</strong></div>`).join("") : '<div class="blank-map">Tu primera memoria protegida va a comenzar el mapa.</div>';
}

$("demoButton").addEventListener("click", async () => { try { $("demoButton").disabled = true; $("demoButton").textContent = "Preparando tu demo…"; const data = await api("/api/demo"); showStudio(data); toast("El workspace de demo está listo. Probá preguntar por la escritura del departamento."); $("studio").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } finally { $("demoButton").disabled = false; $("demoButton").innerHTML = "Entrar al archivo vivo <span>↗</span>"; } });
$("setupButton").addEventListener("click", () => $("onboarding").scrollIntoView({ behavior: "smooth", block: "center" }));
$("workspaceForm").addEventListener("submit", async (event) => { event.preventDefault(); try { const policyChoice = $("inactivityDays").value; const data = await api("/api/create", { owner_id: $("owner").value, passphrase: $("passphrase").value, inactivity_days: policyChoice === "none" ? null : Number(policyChoice) }); showStudio(data); toast("Tu workspace protegido está abierto."); } catch (e) { $("formNote").textContent = e.message; } });
$("unlockButton").addEventListener("click", async () => { try { const data = await api("/api/unlock", { owner_id: $("owner").value, passphrase: $("passphrase").value }); showStudio(data); toast("Tu workspace está desbloqueado."); } catch (e) { $("formNote").textContent = e.message; } });
$("heirButton").addEventListener("click", async () => { try { const data = await api("/api/unlock-heir", { heir_id: $("owner").value, passphrase: $("passphrase").value, heir_key: $("heirKey").value }); showStudio(data); toast("El workspace de heredero se abrió en modo sólo lectura."); } catch (e) { $("formNote").textContent = e.message; } });
$("memoryFile").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file) return; if (file.size > 65536) { $("captureNote").textContent = "Elegí un archivo de texto de menos de 64 KiB."; event.target.value = ""; return; } try { $("memoryBody").value = await file.text(); if (!$("memoryTitle").value) $("memoryTitle").value = file.name.replace(/\.[^.]+$/, ""); $("captureNote").textContent = `${file.name} se cargó localmente. Revisalo antes de protegerlo.`; } catch (_) { $("captureNote").textContent = "No se pudo leer ese archivo como texto."; } });
$("captureForm").addEventListener("submit", async (event) => { event.preventDefault(); try { const selectedFile = $("memoryFile").files[0]; const result = await api("/api/capture", { title: $("memoryTitle").value, body: $("memoryBody").value, filename: selectedFile ? selectedFile.name : null, tags: $("memoryTags").value.split(",").map(v => v.trim()).filter(Boolean) }); showStudio(result.dashboard); $("captureNote").textContent = `Protegida como ${categories[result.record.category] || result.record.category}.`; event.target.reset(); toast("La memoria quedó protegida y se agregó al historial de auditoría."); } catch (e) { $("captureNote").textContent = e.message; } });
$("guideButton").addEventListener("click", async () => { try { const result = await api("/api/heir-guide"); $("guideContent").textContent = result.guide; $("guideCard").hidden = false; $("guideCard").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } });
$("verifyButton").addEventListener("click", async () => { try { const result = await api("/api/integrity"); $("integrityText").textContent = result.valid ? (result.audit.hmac_checked ? "HMAC verificado" : "sólo hash") : "requiere atención"; $("integrityDot").className = `integrity-dot ${result.valid ? (result.audit.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`; const state = result.audit.hmac_checked ? "Protegida con HMAC" : "sólo hash"; toast(result.valid ? `${state}: se verificaron la auditoría y ${result.memory.checked} memorias.` : "La integridad requiere atención.", !result.valid); } catch (e) { toast(e.message, true); } });
$("closeGuide").addEventListener("click", () => $("guideCard").hidden = true);
$("askForm").addEventListener("submit", async (event) => { event.preventDefault(); const answer = $("answer"); try { answer.className = "answer loading"; answer.textContent = "Buscando el hilo relevante…"; const result = await api("/api/ask", { question: $("question").value, allow_narration: $("narrationConsent").checked }); answer.className = "answer"; renderAnswer(answer, result); if (result.narration_error) toast(`${result.narration_error} El resultado determinista no cambió.`, true); } catch (e) { answer.className = "answer"; answer.textContent = e.message; } });
$("lockButton").addEventListener("click", async () => { await api("/api/lock"); $("studio").hidden = true; $("onboarding").hidden = false; $("lockButton").hidden = true; $("navStatus").textContent = "Workspace criptográfico local"; $("passphrase").value = ""; toast("Workspace bloqueado. La frase secreta se borró de este navegador."); window.scrollTo({ top: 0, behavior: "smooth" }); });
