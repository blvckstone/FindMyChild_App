// Tailwind configuration for the stylesheet the user panel links to.
//
// The panel used to load https://cdn.tailwindcss.com — a third-party script that runs in the
// visitor's browser and compiles CSS at runtime. Tailwind itself warns against using it in
// production, and on a page that keeps a login token in browser storage it is a third party with
// full access to that token. The stylesheet is now built once, committed, and served from this
// own origin.
//
// The defaults are left intact on purpose: the CDN compiled with the stock theme, so changing it
// here would silently restyle the site.
module.exports = {
    // Everything the server ships that can contain class names, including the inline scripts in
    // the HTML — those are string literals, so a static scan finds every utility used.
    content: [
        './public/**/*.html',
        './public/js/**/*.js',
        './routes/**/*.js'
    ],
    theme: {
        extend: {}
    },
    plugins: []
};
