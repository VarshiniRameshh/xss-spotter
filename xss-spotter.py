import requests
from bs4 import BeautifulSoup
import re
import webbrowser

def find_reflected_xss(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        if re.search(r'<script[^>]*>[^<]*</script>', str(script)):
            print("Reflected XSS vulnerability found!")
            print("Vulnerable URL: {}".format(url))
            print("Vulnerability Location: <script> tag")
            print("Exploit Payload:")
            payload = script.string
            print_payload(payload)
            print("Vulnerability Description: The application reflects user-supplied data without proper sanitization, allowing the execution of malicious scripts in the browser.")
            return
    print("No reflected XSS vulnerability found on {}".format(url))

def find_stored_xss(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    inputs = soup.find_all('input')
    for input_field in inputs:
        if re.search(r'<input[^>]*>', str(input_field)):
            print("Stored XSS vulnerability found!")
            print("Vulnerable URL: {}".format(url))
            print("Vulnerability Location: Input field - name='{}'".format(input_field.get('name')))
            print("Exploit Payload:")
            payload = input_field.get('value')
            print_payload(payload)
            print("Vulnerability Description: The application stores user-supplied data without proper sanitization, allowing the execution of malicious scripts when the data is rendered back to the user.")
            return
    print("No stored XSS vulnerability found on {}".format(url))

def find_dom_xss(url):
    response = requests.get(url)
    if re.search(r'<script>[^<]*document\.location[^<]*</script>', response.text):
        print("DOM-based XSS vulnerability found!")
        print("Vulnerable URL: {}".format(url))
        print("Vulnerability Location: JavaScript code manipulating the browser's location")
        print("Exploit Payload:")
        payload = response.text.split('<script>')[1].split('</script>')[0]
        print_payload(payload)
        print("Vulnerability Description: The application uses user-supplied data in JavaScript code without proper validation and sanitization, leading to potential manipulation of the browser's location and potential XSS attacks.")
        return
    print("No DOM-based XSS vulnerability found on {}".format(url))

def print_payload(payload):
    print(payload)

# Main program
if __name__ == '__main__':
    domain = input("Enter the domain (e.g., http://example.com): ")

    find_reflected_xss(domain)
    find_stored_xss(domain)
    find_dom_xss(domain)
