# Third-party notices

binoracle is original work. This file records third-party material whose design or code
influenced parts of binoracle, with the applicable licenses preserved.

## REA (morluto/rea)

The design of binoracle's MCP server (`binoracle/mcp_server.py`) — one stdio MCP server that
registers many grounded analysis/exploit tools, and marks results derived from the analysis target
as untrusted content (`_meta.provenance.untrusted_content`) — is adapted from REA
(https://github.com/morluto/rea). No REA source code (TypeScript) is copied; only the architectural
approach was followed, re-implemented from scratch in Python. REA is distributed under the MIT
License:

```
MIT License

Copyright (c) 2026 morluto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
