# IBM Bob Technology Usage

## 1. Project

Is This Safe?

## 2. Purpose of IBM Bob

IBM Bob was used as a development assistance tool during the project lifecycle. Its role was to help with planning, implementation feedback, debugging support, refactoring review, and documentation assistance.

The project itself does not use IBM Bob as the live runtime analysis engine. The deployed application is a static browser-based project that runs on HTML, CSS, and JavaScript logic in the client.

## 3. Development Workflow

The project followed a typical workflow:

Idea / Requirement
→ Planning
→ Implementation
→ Review
→ Debugging
→ Testing
→ Documentation
→ Deployment

IBM Bob supported this workflow by helping structure the concept, speed up implementation iteration, review logic, and support documentation cleanup.

## 4. Development Tasks

### Project Planning

IBM Bob helped organize the initial project concept, feature breakdown, and implementation sequencing for a lightweight static app. This included clarifying the MVP scope and making the architecture easier to reason about.

### Frontend Development

IBM Bob assisted with frontend structure and implementation refinement during the build of the UI, user flow, and result rendering, where applicable.

### Security Analysis Logic

IBM Bob supported the design and refinement of the rule-based detector approach and the project’s risk-scoring structure. The actual logic is still implemented in JavaScript and is clearly based on pattern detection rules rather than a live AI model.

### Debugging

IBM Bob was used during debugging to review issues, investigate app flow, and help validate fixes in the frontend logic and event handling.

### Documentation

IBM Bob assisted with draft documentation and refinement of the project summary, architecture notes, and submission-ready materials.

## 5. Human Oversight

All suggestions, generated code, and documentation were reviewed, tested, and adjusted by the project developers. The final repository reflects actual implementation details and was validated against the current app behavior.

## 6. Runtime Architecture

The deployed application runs as a static front-end web app. It uses:

- HTML for structure
- CSS for styling
- JavaScript for analysis logic and UI behavior
- browser localStorage for recent scan history
- Vercel for deployment

IBM Bob was a development aid and is not the runtime threat-analysis system used by the application.

## 7. Future Use

Future versions could combine the current explainable rule-based detection layer with more advanced AI, ML, or threat-intelligence services. That would be a future enhancement, not a current capability of the deployed application.
