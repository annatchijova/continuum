const layers = {
  core: {
    index: "01",
    overline: "NÚCLEO DETERMINISTA / AUTORIDAD",
    title: "Toda decisión consecuente es reproducible.",
    body: "El núcleo offline clasifica documentos con keywords y regex, recupera y rankea evidencia, aplica políticas de herederos y verifica la auditoría. Nunca depende de un modelo para decidir.",
    points: ["Clasificación y ranking deterministas", "Política de acceso evaluada localmente", "Verificación independiente de la UI"],
  },
  vault: {
    index: "02",
    overline: "VAULT CIFRADO / CUSTODIA",
    title: "El archivo es útil sólo si sigue siendo privado e íntegro.",
    body: "AES-256-GCM protege los datos del vault y los artefactos archivados. Studio habilita el cifrado de base en reposo antes de su primera captura, y el núcleo mantiene el material de claves fuera de la interfaz del navegador.",
    points: ["Cifrado autenticado en reposo", "Artefactos cifrados y direccionados por contenido", "La frase secreta no persiste en la UI"],
  },
  agent: {
    index: "03",
    overline: "CHATGPT ACOTADO / EXPLICACIÓN",
    title: "El lenguaje ayuda a entender; nunca se vuelve autoridad.",
    body: "Con opt-in por request, OpenAI Agents SDK recibe sólo la pregunta, resultado seleccionado por el núcleo y extractos seleccionados. Es stateless, sin trazas y no puede desbloquear, clasificar, rankear ni escribir en el vault.",
    points: ["Consentimiento explícito antes de que salga texto plano", "Narración ligada a fuentes únicamente", "Sin herramientas ni autoridad sobre el vault"],
  },
  studio: {
    index: "04",
    overline: "STUDIO LOCAL / CONEXIÓN HUMANA",
    title: "Una interfaz calma sobre un sistema serio.",
    body: "El servidor local liga sólo a 127.0.0.1 y ofrece recorridos distintos para dueño y heredero. Presenta primero el resultado determinista con fuentes, y luego una narración opcional claramente marcada como no autoritativa.",
    points: ["Vistas de dueño y heredero de sólo lectura", "Fuentes visibles en cada resultado", "Sin dependencia de cloud para usar el núcleo"],
  },
};

const detail = document.getElementById("layerDetail");
document.querySelectorAll(".layer").forEach((button) => {
  button.addEventListener("click", () => {
    const layer = layers[button.dataset.layer];
    document.querySelectorAll(".layer").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    detail.replaceChildren();
    const index = document.createElement("span"); index.className = "detail-index"; index.textContent = layer.index;
    const overline = document.createElement("p"); overline.className = "detail-overline"; overline.textContent = layer.overline;
    const title = document.createElement("h3"); title.textContent = layer.title;
    const body = document.createElement("p"); body.textContent = layer.body;
    const list = document.createElement("ul");
    layer.points.forEach((point) => { const item = document.createElement("li"); item.textContent = point; list.append(item); });
    detail.append(index, overline, title, body, list);
  });
});
