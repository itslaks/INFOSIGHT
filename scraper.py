from flask import Flask, request, jsonify, render_template_string
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Combine HTML, CSS, and JS into one string
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark Web Data Breach Checker</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            margin-bottom: 20px;
        }
        form {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
        }
        input[type="text"] {
            width: 80%;
            padding: 8px;
            margin-bottom: 10px;
        }
        button {
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
        #results {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Dark Web Data Breach Checker</h1>
        <form id="breachForm">
            <label for="userInput">Enter your Email or Phone Number:</label>
            <input type="text" id="userInput" name="userInput" required>
            <button type="submit">Check</button>
        </form>
        <div id="results"></div>
    </div>
    <script>
        document.getElementById('breachForm').addEventListener('submit', function(event) {
            event.preventDefault();

            const userInput = document.getElementById('userInput').value;
            const resultsDiv = document.getElementById('results');

            fetch('/check_breach', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ userInput: userInput })
            })
            .then(response => response.json())
            .then(data => {
                resultsDiv.innerHTML = '';
                if (data.error) {
                    resultsDiv.innerHTML = `<p>Error: ${data.error}</p>`;
                } else if (data.breaches.length > 0) {
                    resultsDiv.innerHTML = '<h2>Breaches Found:</h2>';
                    const ul = document.createElement('ul');
                    data.breaches.forEach(breach => {
                        const li = document.createElement('li');
                        li.textContent = breach;
                        ul.appendChild(li);
                    });
                    resultsDiv.appendChild(ul);
                } else {
                    resultsDiv.innerHTML = '<p>No breaches found</p>';
                }
            })
            .catch(error => {
                resultsDiv.innerHTML = `<p>Error: ${error.message}</p>`;
            });
        });
    </script>
</body>
</html>
"""

def check_email_breach(email):
    url = f"https://haveibeenpwned.com/unifiedsearch/{email}"
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        breaches = []
        breach_elements = soup.find_all('div', class_='pwnedSearchResult')
        for element in breach_elements:
            breach_name = element.get_text(strip=True)
            breaches.append(breach_name)
        return breaches
    elif response.status_code == 404:
        return []
    else:
        return {'error': f"Error: {response.status_code}"}

@app.route('/')
def index():
    return render_template_string(HTML_CONTENT)

@app.route('/check_breach', methods=['POST'])
def check_breach():
    data = request.get_json()
    user_input = data['userInput']
    result = check_email_breach(user_input)
    return jsonify(breaches=result if isinstance(result, list) else [], error=result.get('error') if isinstance(result, dict) else '')

if __name__ == '__main__':
    app.run(debug=True)
