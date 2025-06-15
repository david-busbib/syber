Explanation of HTTP Response Splitting Attack:
     HTTP Response Splitting is a web application attack where an attacker injects unauthorized headers or responses by exploiting an application                that improperly includes user input in HTTP responses. This attack can lead to cache poisoning, or other security vulnerabilities.
     In this implementation, we execute an HTTP Response Splitting attack to poison the proxy cache. The goal is to modify the response for the  /67607.html page, ensuring that users receive a manipulated version containing our attacker-controlled content instead of the original page.

How the Attack Works:
The attack consists of the following steps:

1. Establish a Connection with the Proxy Server
The program creates a TCP connection to the proxy server (192.168.1.202:8080).

2. Craft and Send the Malicious Request
The attacker sends a GET request to /cgi-bin/course_selector, embedding a malicious payload in the query parameter.
This payload includes CRLF (\r\n) sequences to inject unauthorized HTTP headers and response content.
The HTTP Response Splitting attack tricks the proxy server into caching a fake HTTP response with an attacker-controlled body.

3. Trigger the Poisoned Cache Entry
A second trigger request is sent for /67607.html.
This request retrieves the poisoned content from the cache instead of the original /67607.html page.

Choice of Buffer Sizes:
We intentionally kept the buffer sizes small to avoid excessive memory usage while ensuring that they are large enough to hold the required data.
 *The main request buffer is 512 bytes, which is sufficient for constructing the attack payload  while keeping memory allocation efficient.
 *The trigger request buffer is 256 bytes, as it contains a simple request without additional headers.
 *The function replace_spaces_with_encoded() uses a temporary buffer of 256 bytes, ensuring that the encoding of spaces does not exceed reasonable memory constraints.

Choice of the Date (Last-Modified Header):
The Last-Modified header is a critical part of the attack since caching mechanisms often rely on timestamps to determine if a response is still fresh.
We use "yesterday's date" to ensure that the poisoned response appears more recent than older cached versions but is still valid.
This is achieved by:
 * Retrieving the current system time.
 * Subtracting one day (tm_mday -= 1) to make it seem like a slightly outdated but still relevant response.
 * Formatting it according to HTTP standard timestamps (%a, %d %b %Y %H:%M:%S GMT).
Why not use today's date?
 * If the Last-Modified header is set to the exact attack time, the caching mechanism might reject the response as "too new."
 * By setting it to "yesterday," we trick the proxy server into caching it as a legitimate, fresh response.



HTTP Request Smuggling Attack Explanation:
	HTTP Request Smuggling is a sophisticated attack technique that takes advantage of discrepancies in how HTTP requests are processed by 	intermediaries like proxy servers and web servers.
	The attack works by exploiting the mismatch between the Content-Length: 0 header and the Transfer-Encoding: chunked header. The 	proxy server assumes the body is empty due to Content-Length: 0, while the web server processes the chunked body, executing the 	smuggled GET /poison.html request and poisoning the proxy cache.
	The objective of this attack was to poison the proxy cache for the page /page_to_poison.html with the content of /poison.html.
	Steps in the HTTP Request Smuggling Attack:
		1. Establishing a Connection -use socket  to communicate with the proxy server located at 192.168.1.202 on port 8080.
		2. Crafting and Sending the Smuggling Request - 
			The first request is a POST to /doomle.html with headers:
				Content-Length: 0: Specifies no body length for the proxy.
				Transfer-Encoding: chunked: Indicates that the body is encoded in chunks, overriding Content-Length for the web server.
				Content-Length for the web server.
			The chunked body is divided into:
				Chunk Size: 4F\r\n (in hexadecimal, 4F is 79 in decimal, which indicates the size of the chunk).
				Chunk Content: The malicious payload
				(GET /poison.html HTTP/1.1\r\n Host:192.168.1.202:8080\r\nConnection: keep-alive\r\n\r\n), embedded as if it were part of 					the body.
				End of Chunked Body: The 0\r\n\r\n signals the end of the chunked encoding.
		3. Crafting and Sending the Validation Request -
		The validation request is sent to the proxy server using the same socket. This ensures that the proxy server serves the cached 
		(and now poisoned) response for /page_to_poison.html.
		4. Close connection.
		



		
