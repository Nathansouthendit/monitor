// Builds static/app.css from the classes used in templates/.
// Re-run after changing any classes in a template (see README "Rebuilding the CSS").
module.exports = {
  content: ["../templates/**/*.html"],
  theme: { extend: {} },
  plugins: [],
};
