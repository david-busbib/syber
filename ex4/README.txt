Explanation of the Blind SQL Injection Attack 
	

Blind SQL Injection is a technique used to extract sensitive information from a database when direct output is not available ,injecting Boolean-based conditions and analyzes how the web server responds.

The provided C code automates the bitwise extraction of a password using a UNION-based Blind SQL Injection technique.
It constructs a specially crafted payload:
	"""/index.php?order_id=4 UNION SELECT ((ASCII(SUBSTRING(password, %d, 1)) >> %d) & 1) FROM users WHERE id='336224076'--"""
This payload shifts (>> n) and isolates (& 1) each bit of a character’s ASCII value, sending the request to the vulnerable web application.
The server’s response is analyzed to determine whether the extracted bit is 1 or 0.
By repeating this process for every bit in every character (up to a maximum of 10 characters), the script reconstructs the full password. 
indicating that there are no more valid characters to retrieve.
A 1024-byte buffer is used to efficiently store full HTTP responses,while the 512-byte request buffer ensures sufficient space for long SQL injection payloads without excessive memory usage.
The UNION operator is used with a false condition (e.g., order_id=4) to force the database to execute the injected query independently, ensuring that the response includes the extracted bit value without interference from the original application logic.
