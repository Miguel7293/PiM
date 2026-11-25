<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.svg">
  <img alt="PiM — Potential-vulnerability Intelligence Mapper" src="assets/logo-light.svg" width="520">
</picture>

<br/>
<br/>

**Evaluación de vulnerabilidades autoalojada, impulsada por agentes de IA especializados.**
<br/>
Mapea la superficie de ataque, cruza con vulnerabilidades conocidas y entrega un informe estilo SOC — sin atacar nada y sin que tus datos salgan de tu entorno.

<br/>

![Estado](https://img.shields.io/badge/estado-en%20dise%C3%B1o-64748B?style=flat-square)
![Tipo](https://img.shields.io/badge/tipo-vulnerability%20assessment-2563EB?style=flat-square)
![Despliegue](https://img.shields.io/badge/despliegue-self--hosted-0F172A?style=flat-square)
![Licencia](https://img.shields.io/badge/licencia-por%20definir-lightgrey?style=flat-square)

[Qué es](#-qué-es-pim) ·
[Principios](#-principios) ·
[Arquitectura](#-arquitectura-multiagente) ·
[Metodologías](#-metodologías) ·
[Hoja de ruta](#-hoja-de-ruta) ·
[Uso responsable](#%EF%B8%8F-uso-responsable)

</div>

---

## 🔎 Qué es PiM

**PiM (Potential-vulnerability Intelligence Mapper)** es una plataforma que una
organización instala en su propia infraestructura para **evaluar las
vulnerabilidades potenciales** de sus sistemas y proyectos de software.

Un equipo de agentes de IA, cada uno con una tarea acotada, analiza la estructura
del objetivo, la cruza con bases de vulnerabilidades conocidas, construye las
posibles rutas de ataque y genera un **informe estilo SOC** en el que cada
hallazgo queda mapeado a una metodología estándar (MITRE ATT&CK, CWE/CAPEC u
OWASP).

> [!IMPORTANT]
> PiM hace **evaluación de vulnerabilidades**, no *penetration testing*. No
> ejecuta exploits, no modifica sistemas y no envía datos fuera de tu entorno
> salvo que tú lo configures.

### ¿Por qué PiM?

| Problema | Cómo lo aborda PiM |
|---|---|
| El pentesting manual es caro y lento | Automatiza el reconocimiento, el cruce con CVEs y la priorización |
| Las herramientas ofensivas ejecutan exploits reales (riesgo legal y operativo) | Solo lee y reporta: análisis **pasivo** |
| Subir tu mapa de vulnerabilidades a una nube de terceros es inaceptable | **100 % autoalojado**, con bases de vulnerabilidades en espejo local e IA local opcional |
| Los reportes automáticos no dicen qué quedó sin revisar | Mide la **cobertura** contra la metodología: qué se revisó y qué no |

---

## 🧭 Principios

- **Solo analiza y reporta.** Nunca ataca, explota ni modifica el objetivo.
- **Tus datos no salen.** Bases de vulnerabilidades consultadas offline; el único
  dato que puede salir es el que tú decidas enviar a un modelo en la nube.
- **Fuentes estructuradas, nunca búsqueda web libre.** Los CVE vienen de bases
  oficiales, no de un modelo que puede inventarlos.
- **Cada hallazgo con sustento.** Un agente verificador revisa la evidencia antes
  de que algo llegue al informe.
- **Sin dependencia de proveedor.** El modelo de IA es una pieza intercambiable.

---

## 🧩 Arquitectura multiagente

Ningún agente analiza todo: cada uno trabaja con un contexto enfocado, lo que
reduce la sobrecarga y los errores.

```mermaid
flowchart LR
    U([Objetivo + alcance]) --> P[Planificador / Orquestador]
    P --> R[Reconocimiento]
    R -->|grafo de estructura| O[OSINT / CVE]
    O --> A[Análisis de grafo]
    R --> A
    A -->|grafo de ataque| Z[Priorización<br/>CVSS · EPSS · KEV]
    Z --> V[Verificador]
    V -->|hallazgos con evidencia| I[Reportero]
    I --> F([Informe estilo SOC])

    DB[(Espejo local<br/>NVD · OSV · GHSA · KEV · EPSS)] -.-> O
```

| Agente | Responsabilidad |
|---|---|
| **Planificador / Orquestador** | Traduce el objetivo en técnicas a revisar y reparte el trabajo |
| **Reconocimiento** | Identifica tecnologías, versiones, dependencias y puntos de entrada; construye el grafo de estructura |
| **OSINT / CVE** | Cruza cada tecnología y versión con las bases de vulnerabilidades (análisis de composición de software) |
| **Análisis de grafo** | Combina estructura y vulnerabilidades para construir el grafo de ataque |
| **Priorización** | Ordena los hallazgos según CVSS, EPSS y CISA KEV |
| **Verificador** | Confirma que cada hallazgo tenga sustento y reduce falsos positivos |
| **Reportero** | Genera el informe estilo SOC mapeado a la metodología |

### Los dos grafos

| | Grafo de estructura | Grafo de ataque |
|---|---|---|
| **Responde a** | ¿Cómo está construido? | ¿Cómo se movería un atacante? |
| **Nodos** | Componentes, servicios, dependencias, endpoints | Estados que gana el atacante (acceso, privilegios) |
| **Aristas** | Quién se comunica con quién | Acciones entre estados, etiquetadas con su técnica (ATT&CK / CAPEC) |
| **Resultado** | Superficie de ataque | Rutas de ataque encadenadas |

El grafo de estructura se construye primero; el de ataque se construye encima de él.

---

## 📚 Metodologías

| Objetivo evaluado | Metodología |
|---|---|
| Comportamiento de ataque en un entorno o sistema | [MITRE ATT&CK](https://attack.mitre.org) |
| Explicación lineal para audiencias no técnicas | Cyber Kill Chain |
| Fallos en un software específico | [CWE](https://cwe.mitre.org) + [CAPEC](https://capec.mitre.org) |
| Aplicaciones web | [OWASP](https://owasp.org) Testing Guide / Top 10 |

Cada hallazgo y cada ruta de ataque se etiqueta con su técnica, y el informe
muestra la **cobertura** de la evaluación.

---

## 🗄️ Fuentes de vulnerabilidades

Todas se descargan y se consultan **en espejo local**, para que nada sobre tu
stack salga a internet.

| Fuente | Uso |
|---|---|
| [NVD / CVE](https://nvd.nist.gov) | Base de referencia |
| [OSV.dev](https://osv.dev) | Búsqueda por paquete y versión exactos |
| GitHub Security Advisories | Dependencias de código |
| CISA KEV | Vulnerabilidades explotadas activamente |
| [EPSS](https://www.first.org/epss) + CVSS | Probabilidad de explotación y severidad |

> [!NOTE]
> El emparejamiento versión ↔ CVE genera falsos positivos de forma natural.
> Reducirlos (verificador + evidencia por hallazgo) es parte central del proyecto.

---

## 🤖 Modelos de IA

PiM se comunica con los modelos a través de una **interfaz común**; cada
organización conecta el que prefiera al desplegar.

| Modo | Ventaja | Contrapartida |
|---|---|---|
| **Nube** (clave propia de Anthropic, OpenAI, etc.) | Mejor razonamiento | Los datos viajan a un tercero |
| **Local** (p. ej. Ollama) | Nada sale del entorno | Requiere hardware; menor calidad |
| **Híbrido** | Razonamiento pesado en la nube con datos abstraídos | Protege menos de lo que parece; no apto para entornos muy sensibles |

Para compensar modelos locales más débiles:

- **Modelo por agente:** el más potente en el planificador y el verificador; uno ligero en los agentes recolectores.
- **Failover y rotación:** lista ordenada de modelos de respaldo ante fallos o límites.
- **Requisitos documentados:** modelos locales recomendados y el hardware que necesitan.

---

## 📄 Informe final

- Hallazgos clasificados por técnica de la metodología.
- Evidencia y puntuación de cada hallazgo (CVSS / EPSS / KEV).
- Rutas de ataque visualizadas sobre el grafo.
- Cobertura: tácticas y técnicas revisadas y no revisadas.

---

## 🔐 Despliegue y seguridad

- Autoalojado en el entorno de la organización.
- Interfaz enlazada solo a `localhost` por defecto.
- Claves y secretos cifrados en reposo; la llave de cifrado se respalda por separado.

---

## 🗺️ Hoja de ruta

PiM está en **fase de diseño**. Aún no hay instrucciones de instalación.

- [ ] Definir el enfoque: caja blanca (con código fuente) o caja negra
- [ ] Definir la metodología principal según el tipo de objetivo
- [ ] Elegir lenguaje y stack de implementación
- [ ] Definir el modelo de licencia
- [ ] Montar un entorno de pruebas seguro (DVWA, OWASP Juice Shop)
- [ ] Prototipo del agente de reconocimiento y del grafo de estructura
- [ ] Espejo local de NVD / OSV / KEV / EPSS
- [ ] Primer informe estilo SOC de extremo a extremo

---

## ⚖️ Uso responsable

PiM es una herramienta **defensiva**, pero solo debe usarse sobre sistemas
propios o con **autorización expresa** de su titular. Analizar sistemas de
terceros sin permiso puede constituir delito (en Perú, Ley N.º 30096 de Delitos
Informáticos, y normativa equivalente en otros países). Los autores no se
responsabilizan por usos no autorizados.

---

## 💡 Sobre el nombre

**PiM** significa *Potential-vulnerability Intelligence Mapper*: mapea
vulnerabilidades **potenciales** (no confirmadas por explotación) con ayuda de
agentes de **inteligencia** artificial.

El nombre también tiene un guiño al quechua: *pi* significa "¿quién?", y el
sufijo *-m* marca algo que se afirma con evidencia directa. Son las dos ideas de
la herramienta: preguntarse **quién** podría entrar y **sustentar** cada
hallazgo.

---

## 🤝 Contribuir

El proyecto está en etapa temprana. Las ideas, la revisión de la arquitectura y
los issues son bienvenidos.

## 📜 Licencia

Por definir.

<div align="center">
<br/>
<img src="assets/icon.svg" width="40" alt="PiM"/>
<br/>
<sub>Hecho en Cusco, Perú</sub>
</div>
