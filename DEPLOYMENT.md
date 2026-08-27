# GitHub Pages Deployment

This project is a static site and can be published directly to GitHub Pages.

## Steps

1. Push this repository to GitHub.
2. In the GitHub repository, open Settings > Pages.
3. Set the source to:
   - GitHub Actions
4. Save the settings.
5. The workflow in `.github/workflows/pages.yml` will build and deploy the app.

## Live URL

After deployment, the site will be available at:

`https://<your-github-username>.github.io/is-this-safe/`

## Notes

- No backend is required.
- The app runs fully in the browser.
- `localStorage` is used for recent scan history.
