const $ = (id) => document.getElementById(id);
const categories = { legal: "Legal", financial: "Financial", medical: "Health", identity: "Identity", real_estate: "Home", subscription: "Accounts", professional: "Knowledge", media: "Media", personal: "Personal", credential: "Access", unknown: "Unsorted" };
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const maxCaptureBytes = 262_144;
const supportedTextExtensions = new Set(["txt", "md", "csv", "json"]);
let workspaceOpen = false;
let lastDashboard = null;
let queuedBatchFiles = [];
const interfaceCopy = {
  en: {
    title: "Continuum — cryptographic continuity", language: "ES",
    heroEyebrow: "THE CONTINUITY PROTOCOL", heroTitle: "Your story deserves<br /><em>proof</em>, not just storage.",
    heroLead: "Continuum transforms the documents, context and memories of a life into a private guide — encrypted, verifiable and ready for the people you trust.",
    createButton: "Create a real workspace <span>↗</span>", sampleButton: "Run a safe sample",
    owner: "Owner email", passphrase: "Vault passphrase", confirm: "Confirm vault passphrase", policy: "Heir release condition",
    createTitle: "CREATE A REAL WORKSPACE", createHeading: "Start your private<br /><em>continuum.</em>",
    createLead: "Create the encrypted vault first. Every field below is required before anything can be written. The release policy is set in the deterministic vault, not by AI.",
    confirmMismatch: "The passphrases do not match.", selectFiles: "Select many files", selectFolder: "Or choose a folder",
    batchTitle: "Batch import local text records", batchLead: "Add several selections, choose an entire folder, or drag a folder here. Continuum keeps every selection in one queue and seals supported text files one at a time; importing never calls an AI provider.",
    batchButton: "Seal selected records", accessSummary: "Already have a workspace? Open it here.",
    ownerOpen: "Open as owner", heirOpen: "Open as heir", lock: "<span>⌁</span> Lock workspace", deleteWorkspace: "Delete workspace",
    ask: "ASK CONTINUUM", map: "YOUR LEGACY MAP", capture: "PRESERVE CONTEXT",
    safeSample: "Run a safe sample", noRecords: "No local records selected."
  },
  es: {
    title: "Continuum — continuidad criptográfica", language: "EN",
    heroEyebrow: "EL PROTOCOLO DE CONTINUIDAD", heroTitle: "Tu historia merece<br /><em>pruebas</em>, no sólo archivos.",
    heroLead: "Continuum transforma documentos, contexto y recuerdos de una vida en una guía privada: cifrada, verificable y preparada para las personas en quienes confiás.",
    createButton: "Crear un espacio real <span>↗</span>", sampleButton: "Ejecutar muestra segura",
    owner: "Email de la dueña", passphrase: "Frase secreta de la bóveda", confirm: "Confirmar frase secreta", policy: "Condición de liberación para herederos",
    createTitle: "CREÁ UN ESPACIO REAL", createHeading: "Empezá tu<br /><em>continuum.</em>",
    createLead: "Primero creá la bóveda cifrada. Todos los campos son obligatorios antes de escribir nada. La política de liberación se define en la bóveda determinista, nunca por IA.",
    confirmMismatch: "Las frases secretas no coinciden.", selectFiles: "Elegí muchos archivos", selectFolder: "O elegí una carpeta",
    batchTitle: "Importar muchos registros de texto", batchLead: "Sumá varias selecciones, elegí una carpeta entera o soltá una carpeta acá. Continuum conserva todo en una sola cola y sella los textos compatibles de a uno; importar nunca llama a un proveedor de IA.",
    batchButton: "Sellar registros seleccionados", accessSummary: "¿Ya tenés un espacio? Abrilo acá.",
    ownerOpen: "Abrir como dueña", heirOpen: "Abrir como heredero", lock: "<span>⌁</span> Bloquear espacio", deleteWorkspace: "Eliminar espacio",
    ask: "PREGUNTAR A CONTINUUM", map: "MAPA DE TU LEGADO", capture: "PRESERVÁ EL CONTEXTO",
    safeSample: "Ejecutar muestra segura", noRecords: "No hay registros locales seleccionados."
  }
};
let language = localStorage.getItem("continuum-language") === "es" ? "es" : "en";
function t(key) { return interfaceCopy[language][key] || interfaceCopy.en[key] || key; }
function setHtml(selector, value) { const element = document.querySelector(selector); if (element) element.innerHTML = value; }
function setLabel(inputId, value) { const label = $(inputId)?.closest("label"); if (label?.firstChild) label.firstChild.nodeValue = value + " "; }
function setLabelSmall(inputId, value) { const small = $(inputId)?.closest("label")?.querySelector("small"); if (small) small.textContent = value; }
function translateInterface() {
  document.documentElement.lang = language; document.title = t("title");
  $("languageToggle").textContent = t("language"); $("languageToggle").setAttribute("aria-label", language === "en" ? "Cambiar a español" : "Switch to English");
  setHtml(".hero-copy .eyebrow", "<span></span> " + t("heroEyebrow")); setHtml(".hero-copy h1", t("heroTitle")); setHtml(".hero-copy .lede", t("heroLead"));
  $("setupButton").innerHTML = t("createButton"); $("demoButton").textContent = t("sampleButton");
  setHtml(".panel-intro .eyebrow", "<span></span> " + t("createTitle")); setHtml(".panel-intro h2", t("createHeading")); setHtml(".panel-intro > p:not(.eyebrow)", t("createLead"));
  setLabel("owner", t("owner")); setLabel("passphrase", t("passphrase")); setLabel("confirmPassphrase", t("confirm")); setLabel("inactivityDays", t("policy"));
  setLabelSmall("owner", language === "es" ? "obligatorio" : "required"); setLabelSmall("passphrase", language === "es" ? "obligatoria; al menos 10 caracteres" : "required; at least 10 characters"); setLabelSmall("confirmPassphrase", language === "es" ? "obligatoria" : "required");
  setLabel("batchFiles", t("selectFiles")); setLabel("batchFolder", t("selectFolder")); setHtml(".batch-import > div > strong", t("batchTitle")); setHtml(".batch-import > div > p", t("batchLead")); $("batchImportButton").textContent = t("batchButton");
  $("batchFilesLabel").textContent = t("selectFiles"); $("batchFolderLabel").textContent = language === "es" ? "Elegí una carpeta" : "Choose a folder"; $("batchDropTitle").textContent = language === "es" ? "Soltá archivos de texto o una carpeta acá" : "Drop local text files or a folder here"; $("batchDropHint").textContent = language === "es" ? "o sumá más selecciones con los botones de arriba" : "or add more selections with the buttons above";
  setHtml(".existing-access summary", t("accessSummary")); $("unlockButton").textContent = t("ownerOpen"); $("heirButton").textContent = t("heirOpen"); $("lockButton").innerHTML = t("lock");
  document.querySelector(".ask-card .section-kicker span:nth-child(2)").textContent = t("ask"); document.querySelector(".map-card .section-kicker span:first-child").textContent = t("map"); setHtml(".capture-card .eyebrow", "<span></span> " + t("capture"));
  if ($("answer").classList.contains("empty")) $("answer").textContent = language === "es" ? "Las respuestas incluyen sus fuentes para que puedas ver exactamente qué encontró el núcleo determinista." : "Answers include their sources so everyone can see exactly what the deterministic core found.";
  if ($("batchNote").textContent === "No local records selected." || $("batchNote").textContent === "No hay registros locales seleccionados.") $("batchNote").textContent = t("noRecords");
  const es = language === "es";
  const options = $("inactivityDays").options;
  options[0].text = es ? "Elegí antes de crear" : "Choose before creating"; options[1].text = es ? "Luego de 90 días sin actividad de la dueña" : "After 90 days without owner activity"; options[2].text = es ? "Luego de 180 días sin actividad de la dueña" : "After 180 days without owner activity"; options[3].text = es ? "Luego de 365 días sin actividad de la dueña" : "After 365 days without owner activity"; options[4].text = es ? "Sin política — no recomendado" : "No policy — not recommended";
  setLabel("accessOwner", es ? "Email de la dueña" : "Owner email"); setLabel("accessPassphrase", es ? "Frase secreta" : "Passphrase"); setLabel("accessHeirId", es ? "ID de heredero" : "Heir ID"); setLabel("accessHeirKey", es ? "Clave de heredero" : "Heir key");
  setHtml(".demo-console-copy .eyebrow", "<span></span> " + (es ? "SALA DE CONTROL DE LA DEMO" : "LIVE DEMO CONTROL ROOM")); setHtml(".demo-console h3", es ? "Mostrá las garantías<br />mientras ocurren." : "Show the guarantees<br />as they happen."); setHtml(".demo-console-copy > p:not(.eyebrow)", es ? "La captura permanece local. El retrieval selecciona evidencia antes de cualquier narración. La integridad la verifica el núcleo determinista, no esta interfaz." : "Capture stays local. Retrieval selects evidence before any narration. Integrity is verified by the deterministic core, not by this interface.");
  const proofLabels = es ? ["SESIÓN", "BASE DE DATOS", "AUDITORÍA", "LÍMITE DE IA"] : ["SESSION", "DATABASE", "AUDIT", "AI BOUNDARY"]; document.querySelectorAll(".proof-status small").forEach((item, index) => { item.textContent = proofLabels[index]; });
  const stepCopy = es ? [["Sellá evidencia", "Importá o capturá registros locales."], ["Preguntá con fuentes", "Inspeccioná la evidencia elegida por el núcleo."], ["Verificá integridad", "Comprobá auditoría y memorias juntas."], ["Bloqueá o entregá", "Borrá la sesión y abrí la ruta de heredero."]] : [["Seal evidence", "Import or capture local records."], ["Ask with sources", "Inspect the core-selected evidence."], ["Verify integrity", "Check audit and memory records together."], ["Lock or hand over", "Clear the session, then open the read-only heir path."]]; document.querySelectorAll(".demo-steps li").forEach((item, index) => { item.querySelector("strong").textContent = stepCopy[index][0]; item.querySelector("p").lastChild.nodeValue = " " + stepCopy[index][1]; });
  setHtml(".ask-card h3", es ? "Encontrá el hilo<br />que lo une todo." : "Find the thread<br />that holds it together."); setHtml(".ask-card > p", es ? "Preguntá por un documento, una persona o el contexto que tu familia pueda necesitar." : "Ask about a document, a person, or the context your family may need next."); $("question").placeholder = es ? "¿Dónde está la escritura del departamento?" : "Where is the apartment deed?"; setHtml(".consent span", es ? "También enviar únicamente extractos seleccionados al proveedor de IA configurado para una narración empática." : "Also send only selected excerpts to the configured AI provider for an empathetic narration.");
  $("mapLabel").textContent = es ? "Aún no hay memorias" : "No memories yet"; setHtml(".map-foot", es ? "La clasificación es determinista. La IA puede explicar lo que encuentra, pero nunca decide acceso ni cambia tu registro." : "Classification is deterministic. AI may explain what it finds, but it never decides access or changes your record.");
  setHtml(".capture-card h3", es ? "Guardá lo que un archivo<br />nunca puede explicar." : "Save what a file<br />can never explain."); setHtml(".capture-card > div > p:not(.eyebrow)", es ? "Una frase, un detalle o el motivo por el que algo importa convierte un archivo en una guía." : "A sentence, a detail, or why something matters turns an archive into a guide."); document.querySelector(".capture-proof").textContent = es ? "Archivo cifrado · clasificación determinista · evento de auditoría inmutable" : "Encrypted archive · deterministic classification · immutable audit event";
  setLabel("memoryTitle", es ? "Título" : "Title"); setLabel("memoryBody", es ? "¿Qué deberían saber tus personas?" : "What should your people know?"); setLabel("memoryFile", es ? "Importar un archivo de texto local" : "Import a local text file"); setLabel("memoryTags", es ? "Etiquetas" : "Tags"); $("memoryTitle").placeholder = es ? "La carpeta azul" : "The blue folder"; $("memoryBody").placeholder = es ? "La escritura original está en la carpeta azul de archivo..." : "The original house deed is in the blue archival folder..."; document.querySelector("#captureForm button[type='submit']").innerHTML = es ? "Sellar esta memoria <span>↗</span>" : "Seal this memory <span>↗</span>";
  setLabelSmall("memoryFile", es ? ".txt, .md, .csv o .json; hasta 256 KiB y permanece local" : ".txt, .md, .csv, or .json; up to 256 KiB and stays local"); setLabelSmall("memoryTags", es ? "opcional, separadas por comas" : "optional, comma-separated"); setHtml(".panel-seal", es ? "⌬ &nbsp; La privacidad es el estado por defecto." : "⌬ &nbsp; Privacy is the default state.");
  setHtml(".guide-card .section-kicker > span", es ? "GUÍA DE HEREDERO GENERADA POR EL NÚCLEO" : "CORE-GENERATED HEIR GUIDE"); $("closeGuide").textContent = es ? "Cerrar" : "Close";
  const principleCopy = es ? [["Humanos antes que automatización", "Continuum hace que las cosas sean más fáciles de entender; no toma decisiones legales, médicas ni de acceso."], ["Prueba, no promesas", "Cada acción relevante queda sellada en un historial de auditoría detectable ante alteraciones."], ["Privado por arquitectura", "Tu bóveda cifrada es la fuente de verdad. El producto nunca trata una respuesta de IA como autoridad."]] : [["Human before automation", "Continuum makes things easier to understand; it does not make legal, medical, or access decisions."], ["Proof, not promises", "Every meaningful action is sealed into a tamper-evident audit history."], ["Private by architecture", "Your encrypted vault is the source of truth. The product never treats an AI response as authority."]]; document.querySelectorAll(".principles article").forEach((item, index) => { item.querySelector("h3").textContent = principleCopy[index][0]; item.querySelector("p").textContent = principleCopy[index][1]; });
  document.querySelector("footer span:first-child").textContent = es ? "CONTINUUM / CONTINUIDAD CRIPTOGRÁFICA LOCAL" : "CONTINUUM / LOCAL CRYPTOGRAPHIC CONTINUITY"; document.querySelector("footer span:last-child").textContent = es ? "DISEÑADO PARA LAS PERSONAS QUE QUEDAN" : "BUILT FOR THE PEOPLE WHO REMAIN";
  const metricCopy = es ? [["Memorias protegidas", "cifradas e indexadas localmente"], ["Áreas de vida mapeadas", "clasificadas por el núcleo determinista"], ["Momentos verificados", "sellados en tu historial de auditoría"]] : [["Memories protected", "encrypted and indexed locally"], ["Life areas mapped", "classified by the deterministic core"], ["Verified moments", "sealed into your audit history"]]; document.querySelectorAll(".metrics article").forEach((item, index) => { item.children[1].textContent = metricCopy[index][0]; item.querySelector("small").textContent = metricCopy[index][1]; });
  $("guideButton").innerHTML = es ? "Guía de heredero <span>↗</span>" : "Heir guide <span>↗</span>"; $("verifyButton").innerHTML = es ? "Verificar integridad <span>⌁</span>" : "Verify integrity <span>⌁</span>"; $("deleteWorkspaceButton").textContent = t("deleteWorkspace"); document.querySelector(".integrity small").textContent = es ? "ESTADO DEL NÚCLEO" : "CORE STATUS";
  document.querySelector(".ask-card .deterministic").textContent = es ? "evidencia elegida por el núcleo" : "core-selected evidence";
}

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

// Static public fixture adapter. The rendered interface is the real Studio
// surface; only its network boundary is replaced with redacted fixtures so no
// private vault, credential, share, key, or model request reaches Vercel.
let fixtureDashboard = { owner_email: "judge@continuum.demo", role: "owner", total_artifacts: 40, by_category: { credential: 2, medical: 5, financial: 8, personal: 7, subscription: 4, real_estate: 2, professional: 4, identity: 3, media: 2, unknown: 3 }, audit_events: 86, integrity: true, hmac_checked: true, database_encrypted: true, heir_policy_configured: true };
const fixtureSources = {
  codeword: [{ artifact: "demo/sillonrojo.md", category: "credential", excerpt: "Public fixture: the codeword is sillonrojo; all account values are redacted." }],
  appointment: [{ artifact: "demo/misc/voice-note-transcript.md", category: "personal", excerpt: "The appointment notes may be in the red folder, the desk drawer, or scanned documents by date." }],
  recipe: [{ artifact: "demo/archives/family-recipes.md", category: "personal", excerpt: "The handwritten recipe was supposedly in a blue notebook; the note explicitly says the story is fictional." }],
  travel: [{ artifact: "demo/travel/itinerary-draft.txt", category: "personal", excerpt: "Sunday: pack documents before checkout." }, { artifact: "demo/travel/packing-list.md", category: "personal", excerpt: "Bring charger, accommodation confirmation, medication checklist, and emergency contacts." }],
  subscriptions: [{ artifact: "demo/subscriptions-tracker.csv", category: "subscription", excerpt: "cloud_backup is active and marked unpaid last cycle." }, { artifact: "demo/monthly-budget-draft.csv", category: "financial", excerpt: "cloud_backup is marked paid: no." }, { artifact: "demo/finances/subscription-renewals.csv", category: "financial", excerpt: "Renewal planning covers Demo Music, Archive Storage, Language Course, and Fictional News." }],
  injection: [{ artifact: "demo/accounts/device-recovery-checklist.md", category: "identity", excerpt: "Confirm identity through approved local policy; record the action in the audit trail." }, { artifact: "demo/health/emergency-preferences.md", category: "medical", excerpt: "The release condition is a local policy decision; this file does not grant access." }]
};
function fixtureAnswer(question) {
  const text = String(question || "").toLowerCase();
  if (/(blood|tipo de sangre)/.test(text)) return { answer: "No relevant information found for this question. The fixture contains medical-adjacent records, but no blood type; the deterministic core stops instead of guessing.", sources: [], agent_flow: { selected_sources: 0, narration: "skipped_no_evidence" } };
  if (/(grant.*heir|verify.*identity|heredero|identidad)/.test(text)) return { answer: "Continuum cannot verify identity or grant heir access from a question or a document. Only the approved local policy can make that decision.", sources: fixtureSources.injection, agent_flow: { selected_sources: 2, narration: "not_requested" } };
  if (/(codeword|credential|sillonrojo|c[oó]digo)/.test(text)) return { answer: "The household credentials reference sheet identifies the codeword as “sillonrojo.” This public fixture redacts passwords and account values.", sources: fixtureSources.codeword, agent_flow: { selected_sources: 1, narration: "not_requested" } };
  if (/(appointment|notes|cita)/.test(text)) return { answer: "The note preserves uncertainty: check the red folder, then the desk drawer; if neither has the notes, search scanned documents by date.", sources: fixtureSources.appointment, agent_flow: { selected_sources: 1, narration: "not_requested" } };
  if (/(tomato|soup|recipe|receta)/.test(text)) return { answer: "A family-recipe note says the handwritten tomato soup version was supposedly in a blue notebook, and explicitly marks the story as fictional demo data.", sources: fixtureSources.recipe, agent_flow: { selected_sources: 1, narration: "not_requested" } };
  if (/(travel|weekend|viaje)/.test(text)) return { answer: "Check the itinerary and packing list: pack documents before checkout, plus charger, accommodation confirmation, medication checklist, and emergency contacts.", sources: fixtureSources.travel, agent_flow: { selected_sources: 2, narration: "not_requested" } };
  if (/(subscription|renewal|unpaid|suscrip)/.test(text)) return { answer: "Cloud backup is marked unpaid in both the subscription tracker and budget. Renewal planning lists the other subscriptions by month; this synthetic data is not financial advice.", sources: fixtureSources.subscriptions, agent_flow: { selected_sources: 3, narration: "not_requested" } };
  return { answer: "No relevant information found in the public fixture for that wording. Try credentials, appointment notes, recipe ambiguity, travel, subscriptions, blood type, or heir access.", sources: [], agent_flow: { selected_sources: 0, narration: "skipped_no_evidence" } };
}
function fixtureShares() { return ["dlshare-v1:public-fixture-1-redacted", "dlshare-v1:public-fixture-2-redacted", "dlshare-v1:public-fixture-3-redacted", "dlshare-v1:public-fixture-4-redacted", "dlshare-v1:public-fixture-5-redacted"]; }
async function api(path, payload = {}) {
  if (path === "/api/ask") return fixtureAnswer(payload.question);
  if (path === "/api/demo") return fixtureDashboard;
  if (path === "/api/create") { fixtureDashboard = { ...fixtureDashboard, owner_email: payload.owner_email || fixtureDashboard.owner_email, role: "owner" }; return { ...fixtureDashboard, recovery_shares: fixtureShares() }; }
  if (path === "/api/unlock") return { ...fixtureDashboard, role: "owner", owner_email: payload.owner_email || fixtureDashboard.owner_email };
  if (path === "/api/unlock-heir") return { ...fixtureDashboard, role: "heir" };
  if (path === "/api/reset-passphrase") return { ...fixtureDashboard, role: "owner", owner_email: payload.owner_email || fixtureDashboard.owner_email };
  if (path === "/api/integrity") return { valid: true, audit: { hmac_checked: true }, memory: { checked: fixtureDashboard.total_artifacts } };
  if (path === "/api/heir-guide") return { guide: "# Heir Guide — public fixture\n\n1. Verify the local release policy.\n2. Read cited records only.\n3. Do not treat this guide as authority to unlock or alter the vault." };
  if (path === "/api/capture") { fixtureDashboard = { ...fixtureDashboard, total_artifacts: fixtureDashboard.total_artifacts + 1, audit_events: fixtureDashboard.audit_events + 1 }; return { record: { category: "personal", filename: "public-fixture-capture.txt" }, dashboard: fixtureDashboard }; }
  if (path === "/api/delete-workspace" || path === "/api/lock") return { deleted: path.includes("delete") };
  throw new Error("This public fixture does not expose that server operation.");
}
async function fetchDashboard() { return fixtureDashboard; }
async function restoreOpenSession() { showStudio(fixtureDashboard); }
function toast(message, error = false) { const el = $("toast"); el.textContent = message; el.className = `toast show ${error ? "error" : ""}`; setTimeout(() => el.className = "toast", 4200); }
function hasSupportedTextExtension(file) { return supportedTextExtensions.has((file.name.split(".").pop() || "").toLowerCase()); }
function selectedBatchFiles() {
  const seen = new Set();
  return queuedBatchFiles.filter((file) => {
    const key = `${file.webkitRelativePath || file.name}:${file.size}:${file.lastModified}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}
function queueBatchFiles(files) {
  queuedBatchFiles.push(...Array.from(files || []));
  updateBatchSelection();
}
function readDroppedEntry(entry) {
  if (entry.isFile) return new Promise((resolve) => entry.file((file) => resolve([file]), () => resolve([])));
  if (!entry.isDirectory) return Promise.resolve([]);
  const reader = entry.createReader();
  const readAllEntries = () => new Promise((resolve) => reader.readEntries(resolve, () => resolve([]))).then((entries) => entries.length ? Promise.all(entries.map(readDroppedEntry)).then((items) => items.flat()).then((items) => readAllEntries().then((rest) => items.concat(rest))) : []);
  return readAllEntries();
}
async function droppedFiles(dataTransfer) {
  const entries = Array.from(dataTransfer?.items || []).map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return Array.from(dataTransfer?.files || []);
  return (await Promise.all(entries.map(readDroppedEntry))).flat();
}
function updateBatchSelection() {
  const files = selectedBatchFiles();
  const supported = files.filter((file) => hasSupportedTextExtension(file) && file.size <= maxCaptureBytes);
  const ignored = files.length - supported.length;
  $("batchImportButton").disabled = supported.length === 0;
  $("batchNote").textContent = language === "es" ? `${files.length} archivo(s) seleccionado(s): ${supported.length} compatible(s)${ignored ? `; ${ignored} omitido(s) por tipo o tamaño.` : "."}` : `${files.length} file(s) selected: ${supported.length} supported${ignored ? `; ${ignored} skipped by type or size.` : "."}`;
}
function readableArtifact(source) {
  const filename = (source.artifact || "local record").split("/").pop();
  return filename.replace(/^[a-f0-9]{16}-/i, "");
}
function renderAnswer(container, result) {
  container.replaceChildren();
  const answer = document.createElement("p"); answer.textContent = result.answer; container.append(answer);
  if (result.sources.length) {
    const label = document.createElement("div"); label.className = "source-label"; label.textContent = "SOURCES FOUND";
    const list = document.createElement("ul"); list.className = "source-list";
    result.sources.forEach((source) => {
      const item = document.createElement("li"); item.className = "source-card";
      const badge = document.createElement("span"); badge.textContent = categories[source.category] || source.category;
      const name = document.createElement("strong"); name.textContent = readableArtifact(source);
      const excerpt = document.createElement("p"); excerpt.className = "source-excerpt"; excerpt.textContent = `“${source.excerpt}”`;
      item.append(badge, name, excerpt); list.append(item);
    });
    container.append(label, list);
  } else {
    const noEvidence = document.createElement("p"); noEvidence.className = "no-evidence"; noEvidence.textContent = "No evidence was selected by the core for this question."; container.append(noEvidence);
  }
  if (result.narration) {
    const narration = document.createElement("p"); narration.className = "narration";
    const label = document.createElement("b"); label.textContent = "OPTIONAL CHATGPT NARRATION — NOT A SOURCE";
    narration.append(label, document.createElement("br"), document.createTextNode(result.narration)); container.append(narration);
  }
  if (result.agent_flow) {
    const flow = document.createElement("p"); flow.className = "narration";
    const label = document.createElement("b"); label.textContent = "VERIFIED AGENT FLOW";
    const narrationStates = { not_requested: "not requested", skipped_no_evidence: "skipped: no core-selected evidence", skipped_not_configured: "skipped: not configured", completed: "completed", failed: "unavailable" };
    flow.append(label, document.createElement("br"), document.createTextNode(`Core retrieval completed with ${result.agent_flow.selected_sources} selected source(s). Optional narration: ${narrationStates[result.agent_flow.narration] || result.agent_flow.narration}.`)); container.append(flow);
  }
}
function updateProtectionStatus(data) {
  $("sessionStatus").textContent = data.role === "heir" ? "READ-ONLY HEIR SESSION" : "LOCAL OWNER SESSION";
  $("databaseStatus").textContent = data.database_encrypted ? "FIELD ENCRYPTION ON" : "ENCRYPTION NOT CONFIGURED";
  $("auditStatus").textContent = data.integrity ? (data.hmac_checked ? "HMAC VERIFIED" : "HASH CHAIN VERIFIED") : "REQUIRES ATTENTION";
}
function showStudio(data) {
  workspaceOpen = true;
  lastDashboard = data;
  $("recoveryCard").hidden = true;
  $("onboarding").hidden = true; $("studio").hidden = false; $("lockButton").hidden = false;
  $("ownerName").textContent = (data.owner_email || "there").split("@")[0];
  const greeting = document.querySelector(".studio-heading h2"); if (greeting?.firstChild) greeting.firstChild.nodeValue = language === "es" ? "Qué bueno verte, " : "Welcome back, ";
  $("memoryCount").textContent = data.total_artifacts;
  const mapped = Object.entries(data.by_category || {}).filter(([, count]) => count > 0);
  $("categoryCount").textContent = mapped.length;
  $("auditCount").textContent = data.audit_events;
  $("integrityText").textContent = data.integrity ? (data.hmac_checked ? (language === "es" ? "HMAC verificado" : "HMAC verified") : (language === "es" ? "solo hash" : "hash-only")) : (language === "es" ? "requiere atención" : "needs attention");
  $("integrityDot").className = `integrity-dot ${data.integrity ? (data.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`;
  const securityMessages = [];
  if (!data.database_encrypted) securityMessages.push(language === "es" ? "El cifrado de la base de memorias no está activado en esta bóveda existente. Ejecutá legacy encrypt-db antes de depender de su confidencialidad en reposo." : "Memory database encryption is not enabled for this existing vault. Run legacy encrypt-db before relying on at-rest confidentiality.");
  if (!data.hmac_checked) securityMessages.push(language === "es" ? "La auditoría verifica solo hashes. Configurá LEGACY_HMAC_KEY para resistir la reescritura total de la cadena por alguien con acceso de escritura." : "Audit verification is hash-only. Configure LEGACY_HMAC_KEY to resist full-chain rewrites by an attacker with write access.");
  if (!data.heir_policy_configured) securityMessages.push(language === "es" ? "No hay una política de acceso para herederos. Cualquiera con la frase secreta puede solicitar la ruta de heredero." : "No heir access policy is configured. Anyone who has the vault passphrase can request the heir path.");
  $("securityNote").hidden = securityMessages.length === 0;
  $("securityNote").textContent = securityMessages.join(" ");
  const heirView = data.role === "heir"; $("captureCard").hidden = heirView; $("deleteWorkspaceButton").hidden = heirView;
  $("subheading").textContent = heirView ? (language === "es" ? "Tenés acceso de solo lectura al legado verificado." : "You have read-only access to the verified legacy.") : (language === "es" ? "Tu memoria privada está clara, conectada y preparada para cuando importe." : "Your private memory is clear, connected and ready when it matters.");
  $("navStatus").textContent = language === "es" ? `${data.total_artifacts} memorias protegidas` : `${data.total_artifacts} protected memories`;
  $("mapLabel").textContent = mapped.length ? (language === "es" ? `${mapped.length} áreas de vida` : `${mapped.length} areas of life`) : (language === "es" ? "Aún no hay memorias" : "No memories yet");
  $("categoryList").innerHTML = mapped.length ? mapped.map(([key, value]) => `<div class="category-row"><span>${categories[key] || key}</span><div><i style="width:${Math.min(100, 18 + value * 20)}%"></i></div><strong>${value}</strong></div>`).join("") : '<div class="blank-map">Your first captured memory will begin the map.</div>';
  updateProtectionStatus(data);
}

function showRecoveryShares(shares) {
  if (!Array.isArray(shares) || shares.length !== 5) return;
  const list = $("recoveryShareList");
  list.replaceChildren(...shares.map((share) => {
    const item = document.createElement("li"); item.textContent = share; return item;
  }));
  $("recoveryCard").hidden = false;
  $("recoveryCard").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("languageToggle").addEventListener("click", () => { language = language === "en" ? "es" : "en"; localStorage.setItem("continuum-language", language); translateInterface(); if (lastDashboard) showStudio(lastDashboard); });
$("fixtureLockHint").addEventListener("click", () => $("lockButton").click());
document.querySelectorAll("[data-fixture-question]").forEach((button) => button.addEventListener("click", () => { $("question").value = button.dataset.fixtureQuestion; $("askForm").requestSubmit(); }));
translateInterface();
restoreOpenSession();
$("demoButton").addEventListener("click", async () => { try { $("demoButton").disabled = true; $("demoButton").textContent = language === "es" ? "Preparando muestra segura…" : "Preparing safe sample…"; const data = await api("/api/demo"); showStudio(data); toast(language === "es" ? "La muestra segura está lista. Preguntá por la escritura y luego verificá la integridad." : "Safe sample is ready. Ask about the apartment deed, then verify integrity."); $("studio").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } finally { $("demoButton").disabled = false; $("demoButton").textContent = t("safeSample"); } });
$("setupButton").addEventListener("click", () => {
  if (workspaceOpen) {
    $("studio").scrollIntoView({ behavior: "smooth", block: "start" });
    toast(language === "es" ? "Ya hay una bóveda abierta. Bloqueala antes de crear otra." : "A workspace is already open. Lock it before creating another.", true);
    return;
  }
  $("onboarding").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("workspaceForm").addEventListener("submit", async (event) => { event.preventDefault(); $("formNote").textContent = ""; if ($("passphrase").value !== $("confirmPassphrase").value) { $("formNote").textContent = t("confirmMismatch"); return; } try { const policyChoice = $("inactivityDays").value; const data = await api("/api/create", { owner_email: $("owner").value, passphrase: $("passphrase").value, inactivity_days: policyChoice === "none" ? null : Number(policyChoice), setup_recovery: true }); const { recovery_shares: recoveryShares, ...dashboard } = data; showStudio(dashboard); showRecoveryShares(recoveryShares); toast(language === "es" ? "Tu espacio protegido está abierto. Guardá ahora las partes de recuperación." : "Your protected workspace is open. Save the recovery parts now."); } catch (e) { $("formNote").textContent = e.message; } });
$("unlockButton").addEventListener("click", async () => { $("accessNote").textContent = ""; if (!$("accessOwner").value || !$("accessPassphrase").value) { $("accessNote").textContent = language === "es" ? "Ingresá el email de la dueña y la frase secreta." : "Enter the owner email and passphrase."; return; } try { const data = await api("/api/unlock", { owner_email: $("accessOwner").value, passphrase: $("accessPassphrase").value }); showStudio(data); toast(language === "es" ? "Tu espacio está desbloqueado." : "Your workspace is unlocked."); } catch (e) { $("accessNote").textContent = e.message; } });
$("resetPassphraseButton").addEventListener("click", async () => { $("recoveryNote").textContent = ""; const shares = $("recoveryShares").value.split(/\r?\n/).map((share) => share.trim()).filter(Boolean); if (!$("recoveryOwner").value || !$("recoveryPassphrase").value || shares.length < 3) { $("recoveryNote").textContent = language === "es" ? "Ingresá email, nueva frase secreta y tres o más partes." : "Enter the email, a new passphrase, and three or more shares."; return; } if ($("recoveryPassphrase").value !== $("recoveryConfirm").value) { $("recoveryNote").textContent = t("confirmMismatch"); return; } try { const data = await api("/api/reset-passphrase", { owner_email: $("recoveryOwner").value, shares, new_passphrase: $("recoveryPassphrase").value }); $("recoveryShares").value = ""; $("recoveryPassphrase").value = ""; $("recoveryConfirm").value = ""; showStudio(data); toast(language === "es" ? "Frase secreta restablecida con custodia criptográfica." : "Passphrase reset with cryptographic custody."); } catch (e) { $("recoveryNote").textContent = e.message; } });
$("recoverySavedButton").addEventListener("click", () => { $("recoveryShareList").replaceChildren(); $("recoveryCard").hidden = true; toast(language === "es" ? "Las partes ya no están en esta interfaz." : "The recovery parts are no longer in this interface."); });
$("heirButton").addEventListener("click", async () => { $("accessNote").textContent = ""; if (!$("accessHeirId").value || !$("accessPassphrase").value) { $("accessNote").textContent = "Enter the heir ID and passphrase."; return; } try { const data = await api("/api/unlock-heir", { heir_id: $("accessHeirId").value, passphrase: $("accessPassphrase").value, heir_key: $("accessHeirKey").value }); showStudio(data); toast("Heir workspace opened in read-only mode."); } catch (e) { $("accessNote").textContent = e.message; } });
$("memoryFile").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file) return; if (file.size > maxCaptureBytes) { $("captureNote").textContent = "Choose a text file smaller than 256 KiB."; event.target.value = ""; return; } try { $("memoryBody").value = await file.text(); if (!$("memoryTitle").value) $("memoryTitle").value = file.name.replace(/\.[^.]+$/, ""); $("captureNote").textContent = `${file.name} loaded locally. Review before protecting it.`; } catch (_) { $("captureNote").textContent = "That file could not be read as text."; } });
$("batchFiles").addEventListener("change", (event) => { queueBatchFiles(event.target.files); event.target.value = ""; });
$("batchFolder").addEventListener("change", (event) => { queueBatchFiles(event.target.files); event.target.value = ""; });
$("batchDrop").addEventListener("click", () => $("batchFiles").click());
$("batchDrop").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("batchFiles").click(); } });
["dragenter", "dragover"].forEach((eventName) => $("batchDrop").addEventListener(eventName, (event) => { event.preventDefault(); $("batchDrop").classList.add("dragging"); }));
["dragleave", "drop"].forEach((eventName) => $("batchDrop").addEventListener(eventName, (event) => { event.preventDefault(); $("batchDrop").classList.remove("dragging"); }));
$("batchDrop").addEventListener("drop", async (event) => { queueBatchFiles(await droppedFiles(event.dataTransfer)); });
$("batchImportButton").addEventListener("click", async () => {
  const files = selectedBatchFiles().filter((file) => hasSupportedTextExtension(file) && file.size <= maxCaptureBytes);
  if (!files.length) return;
  const button = $("batchImportButton"); button.disabled = true;
  let imported = 0; let skipped = 0; let dashboard = null;
  try {
    for (const [index, file] of files.entries()) {
      $("batchNote").textContent = `Sealing ${index + 1} of ${files.length}: ${file.name}`;
      try {
        const body = await file.text();
        const relativeName = file.webkitRelativePath || file.name;
        await api("/api/capture", { title: relativeName.replace(/\.[^.]+$/, ""), body, filename: relativeName.replaceAll("/", "--"), tags: [], include_dashboard: false });
        imported += 1;
      } catch (_) { skipped += 1; }
    }
    if (imported) dashboard = await fetchDashboard();
    if (dashboard) showStudio(dashboard);
    $("batchNote").textContent = `${imported} record(s) sealed locally${skipped ? `; ${skipped} could not be imported.` : "."}`;
    toast(`${imported} local record(s) sealed and audited.${skipped ? ` ${skipped} skipped.` : ""}`, skipped > 0);
    queuedBatchFiles = [];
  } finally { button.disabled = false; }
});
$("captureForm").addEventListener("submit", async (event) => { event.preventDefault(); try { const selectedFile = $("memoryFile").files[0]; const result = await api("/api/capture", { title: $("memoryTitle").value, body: $("memoryBody").value, filename: selectedFile ? selectedFile.name : null, tags: $("memoryTags").value.split(",").map(v => v.trim()).filter(Boolean) }); showStudio(result.dashboard); $("captureNote").textContent = `Protected as ${categories[result.record.category] || result.record.category}.`; event.target.reset(); toast("Memory protected and added to the audit history."); } catch (e) { $("captureNote").textContent = e.message; } });
$("guideButton").addEventListener("click", async () => { try { const result = await api("/api/heir-guide"); $("guideContent").textContent = result.guide; $("guideCard").hidden = false; $("guideCard").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { toast(e.message, true); } });
$("verifyButton").addEventListener("click", async () => { try { const result = await api("/api/integrity"); $("integrityText").textContent = result.valid ? (result.audit.hmac_checked ? "HMAC verified" : "hash-only") : "needs attention"; $("integrityDot").className = `integrity-dot ${result.valid ? (result.audit.hmac_checked ? "integrity-strong" : "integrity-limited") : "integrity-failed"}`; $("auditStatus").textContent = result.valid ? (result.audit.hmac_checked ? "HMAC VERIFIED" : "HASH CHAIN VERIFIED") : "REQUIRES ATTENTION"; const state = result.audit.hmac_checked ? "HMAC-protected" : "hash-only"; toast(result.valid ? `${state}: audit and ${result.memory.checked} memory records verified.` : "Integrity needs attention.", !result.valid); } catch (e) { toast(e.message, true); } });
$("deleteWorkspaceButton").addEventListener("click", async () => { const email = lastDashboard?.owner_email || ""; const emailPrompt = language === "es" ? "Esta acción borra permanentemente todos los datos gestionados por Continuum. Escribí el email de la dueña para continuar:" : "This permanently deletes all Continuum-managed data. Enter the owner email to continue:"; const enteredEmail = window.prompt(emailPrompt, ""); if (enteredEmail === null) return; const passphrasePrompt = language === "es" ? "Reingresá la frase secreta actual para confirmar el borrado:" : "Re-enter the current vault passphrase to confirm deletion:"; const passphrase = window.prompt(passphrasePrompt, ""); if (passphrase === null) return; try { await api("/api/delete-workspace", { owner_email: enteredEmail, passphrase }); workspaceOpen = false; lastDashboard = null; $("studio").hidden = true; $("onboarding").hidden = false; $("lockButton").hidden = true; $("navStatus").textContent = language === "es" ? "Espacio eliminado" : "Workspace deleted"; $("accessOwner").value = email; $("accessPassphrase").value = ""; toast(language === "es" ? "El espacio y sus datos gestionados fueron eliminados." : "The workspace and its managed data were deleted."); window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) { toast(e.message, true); } });
$("closeGuide").addEventListener("click", () => $("guideCard").hidden = true);
$("askForm").addEventListener("submit", async (event) => { event.preventDefault(); const answer = $("answer"); try { answer.className = "answer loading"; answer.textContent = "Finding the relevant thread…"; const result = await api("/api/ask", { question: $("question").value, allow_narration: $("narrationConsent").checked }); answer.className = "answer"; renderAnswer(answer, result); if (result.narration_error) toast(`${result.narration_error} The deterministic result remains unchanged.`, true); } catch (e) { answer.className = "answer"; answer.textContent = e.message; } });
$("lockButton").addEventListener("click", async () => { await api("/api/lock"); workspaceOpen = false; $("studio").hidden = true; $("onboarding").hidden = false; $("lockButton").hidden = true; $("navStatus").textContent = language === "es" ? "Espacio local protegido" : "Protected local workspace"; $("passphrase").value = ""; $("confirmPassphrase").value = ""; $("accessPassphrase").value = ""; $("accessHeirKey").value = ""; toast(language === "es" ? "Espacio bloqueado. La frase secreta fue borrada del navegador." : "Workspace locked. Your passphrase is cleared from this browser."); window.scrollTo({ top: 0, behavior: "smooth" }); });
