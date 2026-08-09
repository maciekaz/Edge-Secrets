// Wrangler's [[rules]] with type="Text" maps glob-matching imports to
// their file contents as a string at bundle time.
declare module '*.umd.min.js' {
  const content: string
  export default content
}

declare module '*.txt' {
  const content: string
  export default content
}

// Imported for its source text, not its API: the QR encoder runs in the
// browser, so the Worker only ever serves this file.
declare module '*-vendor.js' {
  const content: string
  export default content
}
