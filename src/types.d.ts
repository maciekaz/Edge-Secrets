// Wrangler's [[rules]] with type="Text" maps glob-matching imports to
// their file contents as a string at bundle time.
declare module '*.umd.min.js' {
  const content: string
  export default content
}
