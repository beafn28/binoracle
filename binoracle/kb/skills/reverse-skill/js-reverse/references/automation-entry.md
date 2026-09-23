# Automated Entry

Recommended opening sequence:

1. `js-reverse_new_page` or `js-reverse_navigate_page` to open the page
2. `js-reverse_list_network_requests` to see recent requests
3. `js-reverse_get_request_initiator` to find the call stack
4. `js-reverse_list_scripts` to establish the script scope
5. `js-reverse_search_in_sources` to search for request paths, parameter names, and function names
6. Break on XHR or set a breakpoint on text when necessary

Do not guess how to complete `window`, `document`, `navigator` right away.