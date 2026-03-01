const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");

module.exports = {
  entry: {
    background: "./src/background/index.ts",
    content: "./src/content/index.ts",
    popup: "./src/popup/index.ts",
  },
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "[name].js",
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  plugins: [
    new CopyPlugin([
      { from: "manifest.json", to: "manifest.json" },
      { from: "src/popup/popup.html", to: "popup.html" },
      { from: "src/popup/popup.css", to: "popup.css" },
      // Icons will be added later
    ]),
  ],
  optimization: {
    minimize: true,
  },
};
