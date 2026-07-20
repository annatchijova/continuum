# Continuum

*Una memoria privada y verificable criptográficamente, para las personas que amas y para tu propia vida mientras aún la estás viviendo.*

Licenciado bajo la [Licencia Apache 2.0](LICENSE).

![Continuum Studio](https://img.shields.io/badge/status-hackathon%20prototype-173e3c)

## De dónde surge

Continuum fue creado y es mantenido por Olga Vasilieva. Comenzó como un fork de digital-legacy, un proyecto Apache-2.0 creado por mi hija, Anna Tchijova: un sistema de memoria determinista, cifrado y auditable, construido para el día en que alguien muere y las personas que lo amaban heredan un disco duro sin ningún mapa.

Esa arquitectura —un núcleo que decide y sella antes de consultar a cualquier modelo— resultó útil para muchas más situaciones. Continuum conserva sus garantías y amplía a quién sirve:

- **Una persona hospitalizada o incapacitada de repente**, cuando un familiar necesita hoy las mismas respuestas que necesitaría un heredero.
- **Una persona desorganizada**, para quien «¿dónde puse eso?» es un problema diario.
- **Una persona con TDAH**, que pierde constantemente documentos, contraseñas y citas, y tiempo volviendo a encontrar cosas que solo estaban dispersas.
- **Una persona que ya perdió a un familiar** y ahora intenta entender lo que quedó en un disco duro sin mapa.
- **Un estudiante con cientos de apuntes dispersos** que necesita preguntar «¿dónde escribí sobre X?» y obtener una respuesta con fuentes.
- **Cualquiera que quiera organizar su vida** con el rigor que merece un testamento, sin necesitar una crisis.

## El problema, dicho claramente

Cuando la vida se vuelve difícil de recorrer —porque alguien está desbordado, desorganizado, vive con TDAH o demencia, fue hospitalizado de repente o atraviesa un duelo— las personas necesitan un mapa confiable de lo que importa. Testamentos, seguros, historial médico, contraseñas, fotos familiares y notas cotidianas pueden quedar dispersos entre archivos, carpetas y dispositivos. Nadie debería tener que convertirse en investigador forense de su propia vida solo para encontrar el camino.

La respuesta fácil —«apunta una IA a todos los archivos y deja que la gente haga preguntas»— cambia un problema por otro peor. Un modelo que puede leer mal un documento, inventar un detalle o decidir quién puede acceder a qué no es confiable para un testamento, un diagnóstico, la escritura de una casa ni la información necesaria para conservar la independencia.

La respuesta de Continuum es separar ambas tareas. Un núcleo determinista, cifrado y auditable decide qué existe, qué significa y quién puede verlo. Una IA —usada únicamente con consentimiento explícito para cada solicitud— puede expresar esa respuesta ya decidida en lenguaje humano. Nunca se le pide que decida nada. La claridad debe poder demostrarse, no ser solo plausible.

## Works without an API key / Funciona sin una clave de API

El producto central de Continuum no requiere una clave de API, una cuenta en la nube ni acceso a un modelo. En otras palabras: the deterministic product requires no API key, cloud account, or model access. La clave de OpenAI se usa only for the optional, per-request GPT-5.6 narration layer, es decir, únicamente para la capa opcional de narración activada por solicitud. El propietario puede crear y bloquear una bóveda, capturar y cifrar recuerdos, clasificar y recuperar evidencias, verificar la cadena de auditoría, configurar condiciones de acceso y utilizar los flujos de propietario y heredero completamente sin conexión. Desactivar la narración nunca cambia una fuente, clasificación, decisión de acceso ni resultado de integridad.

## Qué hace realmente Continuum

- **Comprende una vida entera de documentos.** Incorpora textos y los clasifica por dominio mediante reglas deterministas; ningún modelo adivina qué es un documento.
- **Responde preguntas con fuentes, no con impresiones.** El comando legacy query devuelve una respuesta ordenada y citada a partir del material del propietario.
- **Recuerda como las personas.** Un campo inspirado en TF-IDF + STDP refuerza lo que se recuerda con frecuencia y permite que lo que no se usa se desvanezca hacia FORGOTTEN: nunca se elimina y siempre es auditable.
- **Habla solo cuando se la invita.** Con OPENAI_API_KEY configurada y aceptación explícita por pregunta, GPT-5.6 puede narrar la evidencia ya seleccionada. No puede desbloquear una bóveda, decidir qué es evidencia, ordenar resultados ni conceder acceso.
- **Entrega el hogar de forma segura.** Los propietarios definen herederos y la condición exacta que libera el acceso: inactividad, fecha fija, clave compartida o interruptor manual. El núcleo las evalúa localmente.
- **Sobrevive al peor escenario.** Shamir Secret Sharing permite que K de N personas reconstruyan el acceso juntas, mientras que cualquier grupo de K-1 no aprende nada.

## El límite ético: la IA narra, nunca decide

No es un eslogan: es un límite arquitectónico aplicado en el código y probado directamente:

- El núcleo determinista selecciona, ordena, clasifica y concede acceso antes de llamar a cualquier modelo. El modelo recibe solo la respuesta decidida y los fragmentos elegidos por el núcleo.
- La narración requiere aceptación por pregunta, es sin estado y no se rastrea. El modelo debe narrar únicamente lo recibido: nunca inventar, reordenar, omitir ni agregar hechos.
- Desactivar el narrador cambia únicamente la redacción, nunca las fuentes ni la autorización. Si pudiera alterar una decisión, sería un defecto de arquitectura.
- El registro deja constancia de que hubo narración y de cuántas fuentes participaron, pero nunca de la pregunta sensible ni del texto narrado.

## Probar el producto

~~~bash
python3 -m continuum_web.server --workspace .continuum-demo
~~~

Abre http://127.0.0.1:8787 y elige **Explore a safe demo**. Esto crea solo datos ficticios en el espacio de trabajo indicado por --workspace. Para el script completo, la arquitectura y el límite de integración con OpenAI, consulta [HACKATHON.md](HACKATHON.md).

Studio no utiliza dependencias de framework web. La CLI original sigue disponible para administrar bóvedas directamente. Tiene puntos de entrada separados para propietarios y herederos; el acceso de los herederos es de solo lectura. Al crear un espacio de trabajo, el propietario debe elegir explícitamente una condición de liberación: un período de inactividad o la opción sin política. La interfaz nunca asigna una política en silencio.

Los propietarios pueden capturar una nota o importar un archivo local .txt, .md, .csv o .json después de revisar su texto en el navegador. La incorporación de archivos binarios y PDF sigue estando disponible en la CLI.

Los espacios nuevos activan el cifrado de memory.db antes de la primera captura y archivan cada texto en el almacén de artefactos cifrado. Las bóvedas existentes conservan su configuración; usa legacy encrypt-db para migrar una bóveda antigua deliberadamente.

## Narración opcional con ChatGPT

Configura OPENAI_API_KEY e instala el Agents SDK opcional para activar la narración con GPT-5.6 sobre evidencias recuperadas localmente. También debes marcar explícitamente el consentimiento en la interfaz. El núcleo determina la recuperación y el acceso; el agente solo explica las fuentes seleccionadas.

~~~bash
export OPENAI_API_KEY='...'
pip install -e '.[agents]'
python3 -m continuum_web.server
~~~

## Principios de diseño

- **Determinista.** Clasificación, puntuación (aritmética Fraction, sin flotantes en decisiones) y Guía del Heredero producen el mismo resultado para la misma entrada.
- **Auditable.** Cada operación se sella en una cadena de hash de solo anexado (SHA-256 más HMAC opcional). verify_legacy.py usa únicamente la biblioteca estándar.
- **Cifrado.** El índice legacy vive en una bóveda AES-256-GCM (PBKDF2-SHA256, 260.000 iteraciones). Los archivos pueden archivarse en el ArtifactStore cifrado.

## Arquitectura

El paquete del prototipo todavía se llama legacy; cambiarle el nombre es un paso posterior.

~~~
legacy/
├── core/       canonicalización, cadena de hash, auditoría, custodia, bloqueo temporal,
│               cifrado de base de datos y bloqueo de procesos
├── ingestion/  taxonomía documental y clasificador determinista
├── memory/     campo de memoria TF-IDF + STDP y consolidación
├── knowledge/  extractor cifrado de conocimiento profesional
├── vault/      bóveda AES-GCM, almacén de artefactos y condiciones de acceso
└── agent/      orquestación de propietario/heredero, consultas, guía, doctor y exportación
~~~

## Estructura del repositorio

El repositorio contiene la superficie del producto, el núcleo determinista, las
primitivas de seguridad, Studio local y una amplia suite de regresión. El árbol
omite bytecode generado, espacios de trabajo locales y metadatos de empaquetado.

~~~text
continuum/
├── continuum_web/                 Studio local y presentación en el navegador
│   ├── server.py                  servidor loopback y coordinador de sesiones
│   ├── narrator.py                límite opcional y acotado de narración GPT-5.6
│   └── static/                    interfaces de dueño, heredero, español y jueces
├── legacy/                        núcleo determinista del producto
│   ├── agent/                     consultas, agente de memoria, guía, exportación, doctor
│   ├── core/                      auditoría, canonicalización, cifrado de DB,
│   │                               bloqueos, custodia Shamir y time-locks
│   ├── ingestion/                 taxonomía documental y clasificador por reglas
│   ├── knowledge/                 extracción cifrada de conocimiento profesional
│   ├── memory/                    campo de memoria TF-IDF/STDP y consolidación
│   └── vault/                     bóveda AES-GCM, almacén de artefactos y políticas
├── cli/                           punto de entrada de línea de comandos
├── tests/                         pruebas unitarias, integración, propiedades y seguridad
│   ├── test_security_r*.py        regresiones documentadas de red team
│   ├── test_vault*.py             cobertura de bóveda y cifrado
│   ├── test_memory*.py            recuperación, memoria y cifrado de DB
│   └── test_*.py                  auditoría, custodia, exportación, políticas y Studio
├── vercel-judges-preview/         preview estático para jueces
├── HACKATHON.md                   arquitectura de la entrega y flujo de demo
├── KNOWN_LIMITATIONS.md           límites explícitos y fronteras de confianza
├── STRESS_TEST.md                 protocolo seguro para probar datos del dueño
├── stress-oracle.template.md      plantilla de evaluación privada
├── RETRIEVAL_FIX_2026-07-19.md    corrección y justificación de retrieval
├── verify_legacy.py                verificador de auditoría sin dependencias externas
├── pyproject.toml                 metadatos y dependencias opcionales
├── LICENSE                        Licencia Apache 2.0
└── README-ES.md                   guía traducida del producto y su arquitectura
~~~

Es un paquete Python funcional con CLI, aplicación web local, almacenamiento
cifrado, un núcleo comprobable por separado, superficies de presentación para
jueces y regresiones de seguridad. La interfaz del navegador es solo la capa de
presentación; el comportamiento autoritativo permanece en el núcleo legacy.

## Inicio rápido

~~~bash
pip install -e ".[dev,memory]"   # instala el comando legacy
legacy init --inactivity-days 90
legacy ingest ~/Documents --knowledge
legacy archive ~/Documents/will.pdf
legacy query "where is the house contract?"
legacy guide --output guide.md
legacy heir-add maria_daughter --name "Maria" --with-key
legacy heir-revoke maria_daughter
legacy export ~/legacy_for_maria
legacy bundle-verify ~/legacy_for_maria
legacy rekey
legacy encrypt-db
legacy doctor
legacy verify
~~~

## Custodia y recuperación

El escenario central es que la frase de contraseña muera con el propietario. Shamir Secret Sharing distribuye una clave entre N custodios: **cualquier K puede reconstruirla, mientras que K-1 no aprende nada**. Es una garantía matemática sobre GF(2⁸), no una promesa de la lógica de la aplicación.

~~~bash
legacy custody setup --shares 5 --threshold 3
legacy custody status
legacy custody recover --set-passphrase --actor olga
~~~

Rotar la frase de contraseña (rekey) no invalida las partes: la bóveda v2 usa compartimentos de claves independientes. Volver a ejecutar custody setup sí revoca el conjunto anterior.

Un rompecabezas opcional de bloqueo temporal sin conexión ofrece una tercera vía:

~~~bash
legacy custody calibrate --days 30
legacy custody timelock-setup --squarings 260000000000
legacy custody timelock-recover --set-passphrase --actor olga
~~~

El bloqueo temporal impone un mínimo de trabajo computacional secuencial, no una fecha de calendario. Consulta KNOWN_LIMITATIONS.md antes de confiar en él.

## Modelo de seguridad

| Garantía | Mecanismo |
|---|---|
| Confidencialidad del índice Legacy | Bóveda AES-256-GCM v2 con compartimentos de claves independientes |
| Confidencialidad e integridad de archivos | GCM más direccionamiento de contenido SHA-256 |
| Confidencialidad de bases de datos en reposo | Cifrado de campos AES-GCM a nivel de aplicación, activable mediante encrypt-db |
| Recuperación tras perder la frase de contraseña | Custodia Shamir K-de-N |
| Rotación segura de la frase de contraseña | Reenvoltura del compartimento sin recifrar la carga útil |
| Operaciones que evidencian manipulaciones | Cadena SHA-256; HMAC resiste el recálculo |
| Ausencia de colisiones silenciosas entre instancias CLI | AgentLock cooperativo |

El sistema no promete detectar contradicciones semánticas, resolver entidades, garantizar atomicidad entre bases SQLite separadas ni ofrecer un bloqueo temporal criptográfico basado en la hora. Estas limitaciones están documentadas en [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). Léelo antes de confiarle datos reales.

## Aprendido a la fuerza: siete rondas internas de red team

La confianza en un sistema que protege testamentos e historias clínicas no puede basarse en un README. Antes de que Continuum adoptara su nombre actual, su predecesor pasó por siete rondas internas documentadas de red team. Cada una planteó un fallo plausible, dedujo una consecuencia comprobable y la confirmó contra el código activo. Cada ronda incorporó una corrección y una prueba de regresión; no se debilitó ninguna prueba hasta que pasara.

| Ronda | Alcance | Hallazgos representativos |
|---|---|---|
| R1 | Revisión inicial, 8 hallazgos | Divergencia TOCTOU del hash en contenido en memoria; recorrido de enlaces simbólicos; comparación de frases de contraseña no constante en tiempo |
| R2 | Memoria y auditoría, 10 hallazgos | Sellado no atómico de la bóveda; refuerzo/olvido sin autenticación ni auditoría; contradicciones semánticas silenciosas |
| R3 | Consistencia criptográfica, 6 hallazgos | memory.db fuera de la cadena de confianza; crecimiento ilimitado de puntuaciones; brecha de atomicidad entre almacén y auditoría |
| R4 | Sellado de la bóveda | seal() podía reemplazar la bóveda con una frase incorrecta y destruir la custodia |
| R5 | Estructura del texto cifrado | El prefijo del texto cifrado era texto plano válido y explotable |
| R6 | Índice de búsqueda | Un índice FTS5 sobrevivía al cifrado con el texto plano legible |
| R7 | Política de acceso y supresión | La clave de un segundo heredero bloqueaba a todos; un atacante podía cambiar una memoria a FORGOTTEN fuera de la auditoría |

Las correcciones de R7 ahora se distribuyen con pruebas específicas en tests/test_security_r7.py:

- **Bloqueo de múltiples herederos.** Las condiciones exigen por defecto todas las condiciones enumeradas. Las claves de los herederos ahora forman su propio grupo OR: la clave de cualquier heredero satisface esa parte de la política.
- **Supresión invisible.** El estado determina si un heredero podrá volver a ver una memoria, pero es metadato no autenticado. La comprobación cruza cada memoria FORGOTTEN con la auditoría; una supresión sin un evento MEMORY_FORGOTTEN se marca como manipulación.

Por eso la postura de seguridad de este README es una afirmación sobre un sistema atacado repetidamente en papel por sus propios creadores, no sobre un sistema que nadie haya intentado romper.

## Pruebas

~~~bash
python -m pytest -q
~~~

## Variables de entorno

| Variable | Efecto |
|---|---|
| LEGACY_DATA_DIR | Directorio de datos (por defecto ~/.legacy) |
| LEGACY_OWNER_ID | Identificador del propietario |
| LEGACY_HMAC_KEY | Clave HMAC hexadecimal para el registro (se recomiendan al menos 32 bytes) |
| LEGACY_HMAC_KEY_FILE | Ruta a un archivo que contiene los bytes de la clave |

## Sesión del hackathon

Identificador de sesión de Codex:

019f685f-ad37-70c0-9be9-990001e4e9fe

Este identificador se incluye para la atribución del hackathon y la trazabilidad del desarrollo. No es una credencial ni concede acceso al repositorio o a sus datos.

## El legado humano

*Canción de [Olga Vasilieva](https://suno.com/song/049456fe-7d61-4820-8ccd-fb0377b7e925)*

**Verso 1**<br>
Una fotografía entre sus manos,<br>
un rostro conocido, perdido entre los granos.<br>
Un nombre que se apaga, una habitación callada,<br>
un recuerdo que desaparece demasiado de prisa.<br>
Mil archivos, mil días,<br>
perdidos en una neblina digital olvidada.<br>
Una vida de momentos, sueños y lágrimas,<br>
esperando a través de los años que pasan.

**Pre-estribillo**<br>
Y si las voces empiezan a apagarse,<br>
si cada camino se convierte en un laberinto,<br>
debe haber algo que podamos hacer<br>
para mantener las historias resplandeciendo.

**Estribillo**<br>
Somos más que datos, más que tiempo,<br>
más que un archivo o una línea rota.<br>
Cada latido, cada huella,<br>
cada recuerdo tiene un lugar.<br>
Cuando el camino deja de ser claro,<br>
cuando desaparecen las respuestas,<br>
construiremos un puente para ver...<br>
un legado humano.

**Verso 2**<br>
Una mente inquieta que no puede parar,<br>
mil pensamientos que vienen y van.<br>
Buscando palabras, buscando luz,<br>
intentando encontrar lo que parece correcto.<br>
Una mano silenciosa dentro de una habitación,<br>
una voz esperando entre la oscuridad.<br>
Una hija preguntando por dónde empezar,<br>
buscando fragmentos del corazón de su padre.

**Puente**<br>
No una copia, no una máquina,<br>
no una sombra de lo que fue.<br>
Sino una guía protegida y confiable,<br>
que guarda mundos preciados en su interior.<br>
Recuerdos cifrados, almacenados con seguridad,<br>
cada capítulo, cada palabra.<br>
Auditado, protegido, claro y verdadero,<br>
un camino para quienes te sigan.

**Estribillo final**<br>
Somos más que datos, más que tiempo,<br>
más que un archivo o una línea rota.<br>
Cada historia, cada nombre,<br>
merece vivir más allá del marco.<br>
Cuando los recuerdos se desvanezcan,<br>
cuando el mañana oculte el presente,<br>
Continuum nos ayudará a encontrar...<br>
el alma humana que dejamos atrás.

**Coda**<br>
Una vida puede cambiar.<br>
Un recuerdo puede desvanecerse.<br>
Pero cada historia<br>
puede permanecer.
