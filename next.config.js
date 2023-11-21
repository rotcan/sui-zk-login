/** @type {import('next').NextConfig} */
const CopyPlugin = require("copy-webpack-plugin");

const nextConfig = {
    reactStrictMode: false
}

module.exports = nextConfig;
// module.exports = {
//     webpack: (config) => {
//         // append the CopyPlugin to copy the file to your public dir
//         config.plugins.push(
//           new CopyPlugin({
//             patterns: [
//               { from: "node_modules/webextension-polyfill/dist", to: "public/" },
//             ],
//           }),
//         )
    
//         // Important: return the modified config
//         return config
//       }
// }
