# Deployment

## Live Application

https://is-this-safe-07.vercel.app/

## Deployment Platform

Vercel

## Deployment Process

The project is a static front-end application and does not require a backend service. It can be deployed directly to Vercel from the repository.

The current deployment process is:

1. Push repository changes to GitHub.
2. Import the repository into Vercel.
3. Use the default static site settings for the project.
4. Confirm the deployment builds successfully.
5. Publish the deployment to the production domain.

The application is designed to run from static files without build tooling or environment configuration.

## Environment Variables

No environment variables are required for the current application.

## Production Verification

The following checks are relevant for the live deployment:

- the application loads successfully in the browser
- the input form accepts suspicious text and optional URLs
- the analysis engine produces a verdict and risk score
- warning sign cards and recommended actions render correctly
- recent scan history is saved in browser localStorage
- the page remains usable on desktop and smaller screens

## Notes

- The current runtime is entirely client-side.
- No secret keys, API tokens, or backend credentials are required for the deployed app.
- The deployment is intended for demo and awareness use, not for production-grade threat intelligence processing.
