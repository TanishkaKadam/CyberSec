# Import required libraries
import requests
import re
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import matplotlib.pyplot as plt
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib.robotparser
import io
from PIL import Image, ImageTk  # For handling images
import webbrowser  # For opening video links

# Tkinter imports
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import threading

# ---- 1. Data Collection (Placeholder Dataset) ----
# Safe samples (normal requests)
safe_samples = [
    {"request": "https://example.com/search?q=safe", "response": "Search results for safe"} for _ in range(50)
]

# Vulnerable samples (malicious requests)
vuln_samples = [
    {"request": "https://example.com/search?q=';DROP TABLE users;--", "response": "SQL syntax error"} for _ in range(50)
]

# Combine data and labels
data = safe_samples + vuln_samples
labels = [0] * len(safe_samples) + [1] * len(vuln_samples)

# ---- 2. Feature Extraction ----
def extract_features(request_response, vuln_type="generic"):
    """Extracts features from a request-response dictionary based on the vuln_type."""
    text = request_response["request"] + " " + request_response["response"]

    if vuln_type == "sql_injection":
        sql_keywords = r"(SELECT|UNION|DROP|INSERT|DELETE|UPDATE|WHERE|OR|AND)"
        sql_features = len(re.findall(sql_keywords, text, re.IGNORECASE))
        return text + f" sql_keywords:{sql_features}"  # Add SQL-specific features
    elif vuln_type == "xss":
        xss_payloads = r"(<script>|onerror=|javascript:)"
        xss_features = len(re.findall(xss_payloads, text, re.IGNORECASE))
        return text + f" xss_payloads:{xss_features}"  # Add XSS-specific features
    else:  # Generic features
        return text

def heuristic_checks(url, response_text):
    """Performs heuristic checks for common vulnerabilities."""
    vulnerabilities = []

    # Directory Listing
    if "Index of /" in response_text:
        vulnerabilities.append({"type": "Directory Listing", "severity": "Low", "url": url})

    # Exposed Configuration Files (example)
    if url.endswith(".env") or url.endswith("web.config"):
        vulnerabilities.append({"type": "Exposed Config File", "severity": "High", "url": url})

    return vulnerabilities

# ---- 3. Model Training ----
# Extract features from the dataset
features = [extract_features(item) for item in data]

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

# Vectorize text data using TF-IDF
vectorizer = TfidfVectorizer()
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train a Logistic Regression model
model = LogisticRegression(class_weight='balanced')
model.fit(X_train_vec, y_train)

# Evaluate the model
y_pred = model.predict(X_test_vec)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")
print(classification_report(y_test, y_pred, zero_division=0))

# ---- 4. Session Creation for Retry Mechanism ----
def create_session(retries=3, backoff_factor=0.5, status_forcelist=(500, 502, 504)):
    """Creates a requests Session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# ---- 5. Scanning Function ----
def scan_url(url, model, vectorizer, session, output_text, progress_bar):
    """Scans a single URL for vulnerabilities using the trained model."""
    vulnerabilities = []  # Collect detected vulnerabilities

    try:
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        response = session.get(url, headers=headers, timeout=10)  # Increased Timeout
        response.raise_for_status()
        response_text = response.text

        # Run heuristic checks (before ML)
        vulnerabilities.extend(heuristic_checks(url, response_text))

        # Run ML-based scan
        text = extract_features({"request": url, "response": response_text}, vuln_type="generic")  # Extract generic features
        features_vec = vectorizer.transform([text])
        prediction = model.predict(features_vec)[0]

        if prediction == 1:
            vulnerabilities.append({"type": "Potential Vulnerability", "severity": "Medium", "url": url})  # Example Vulnerability

        # Output vulnerabilities to GUI
        for vuln in vulnerabilities:
            output_text.insert(tk.END, f"🔍 Vulnerability Found: Type: {vuln['type']}, Severity: {vuln['severity']}, URL: {vuln['url']}\n", "vulnerability")
            output_text.see(tk.END)
        return vulnerabilities

    except requests.exceptions.RequestException as e:
        error_message = f"[ERROR] Could not scan {url}: {e}\n"
        output_text.insert(tk.END, error_message)  # Error message in plain black text
        output_text.see(tk.END)
        return vulnerabilities  # Return empty list if there's an error

# ---- 6. Crawling Function ----
def crawl_and_scan(base_url, model, vectorizer, session, output_text, progress_bar, max_depth=2, max_pages=100):
    """Crawls a website and scans URLs."""
    visited = set()
    all_vulnerabilities = []  # To store the results (Safe, Vulnerable, Error)
    pages_crawled = 0  # Keep track of pages crawled

    # Parse Robots.txt
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(base_url + "/robots.txt")
    try:
        rp.read()  # Read the robots.txt file
    except:
        output_text.insert(tk.END, "⚠️ Could not read robots.txt, proceeding without it.\n", "warning")

    def crawl(url, depth):
        nonlocal all_vulnerabilities, pages_crawled  # Allow modification of the 'results' list in the outer scope

        if depth > max_depth or url in visited or pages_crawled >= max_pages or not rp.can_fetch("*", url):  # Check robots.txt
            return

        visited.add(url)
        pages_crawled += 1  # Increment the counter
        output_text.insert(tk.END, f"🌐 Crawling: {url}\n", "info")  # Output to GUI
        output_text.see(tk.END)

        try:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
            }
            response = session.get(url, headers=headers, timeout=10)  # Increased Timeout
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'lxml')  # Use a more robust parser like lxml

            # Scan the URL
            vulnerabilities = scan_url(url, model, vectorizer, session, output_text, progress_bar)
            all_vulnerabilities.extend(vulnerabilities)  # Store the results

            # Update progress bar
            progress = (pages_crawled / max_pages) * 100
            progress_bar['value'] = progress
            update_progress_bar_color(progress_bar, progress)  # Update progress bar color
            root.update_idletasks()

            # Find links and crawl recursively
            for link in soup.find_all('a', href=True):
                absolute_url = requests.compat.urljoin(url, link['href'])
                crawl(absolute_url, depth + 1)

        except requests.exceptions.RequestException as e:
            error_message = f"[Could not crawl {url}: {e}\n"
            output_text.insert(tk.END, error_message)  # Error message in plain black text
            output_text.see(tk.END)
            all_vulnerabilities.append({"type": "Error", "severity": "N/A", "url": url})  # Store the error result

    crawl(base_url, 0)
    return all_vulnerabilities  # Return the list of results

# ---- 7. Reporting & Visualization ----
def report_and_visualize(vulnerabilities, output_text):
    """Reports and visualizes scan results with references to common vulnerabilities and their remediation guides."""

    # Vulnerability references
    vulnerability_references = {
        "Directory Listing": {
            "description": "Directory listing is a web server configuration issue that allows an attacker to view the contents of directories on the server.",
            "remediation": "Disable directory listing in your web server configuration.",
            "reference_link": "https://owasp.org/www-community/attacks/Path_Traversal",
            "video_link": "https://www.youtube.com/watch?v=example1"
        },
        "Exposed Config File": {
            "description": "Exposed configuration files can reveal sensitive information such as database credentials, API keys, and other secrets.",
            "remediation": "Ensure that configuration files are not accessible via the web server.",
            "reference_link": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "video_link": "https://www.youtube.com/watch?v=example2"
        },
        "Potential Vulnerability": {
            "description": "A potential vulnerability was detected based on the machine learning model's prediction.",
            "remediation": "Review the URL and response for any suspicious patterns or payloads.",
            "reference_link": "https://owasp.org/www-project-top-ten/",
            "video_link": "https://www.youtube.com/watch?v=example3"
        }
    }

    # Print vulnerabilities
    if vulnerabilities:
        output_text.insert(tk.END, "\n📊 Vulnerabilities Found:\n", "info")
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            output_text.insert(tk.END, f"  - 🔍 Type: {vuln_type}, Severity: {vuln['severity']}, URL: {vuln['url']}\n", "vulnerability")
            if vuln_type in vulnerability_references:
                output_text.insert(tk.END, f"    📝 Description: {vulnerability_references[vuln_type]['description']}\n", "info")
                output_text.insert(tk.END, f"    🛠️ Remediation: {vulnerability_references[vuln_type]['remediation']}\n", "info")
                output_text.insert(tk.END, f"    🔗 Reference: {vulnerability_references[vuln_type]['reference_link']}\n", "info")
                # Add a button to open the video link
                video_button = tk.Button(
                    output_text,
                    text="🎥 Watch Video ",
                    command=lambda link=vulnerability_references[vuln_type]['video_link']: webbrowser.open(link),
                    bg="red",  # Red background
                    fg="white",  # White text
                    activebackground="darkred",  # Darker red on hover
                    activeforeground="white",  # White text on hover
                    relief=tk.FLAT,  # Flat button style
                    font=("Helvetica", 8, "bold")  # Modern font
                )
                # Center the button in the output text box
                output_text.window_create(tk.END, window=video_button, align="center")
                output_text.insert(tk.END, "\n")
    else:
        output_text.insert(tk.END, "✅ No vulnerabilities found.\n", "success")

    # Visualize
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln['severity']
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts[severity] = 1

    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    colors = ['red', 'orange', 'yellow', 'green', 'gray']  # Customize colors
    plt.figure(figsize=(8, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('Web Application Scan Results (Severity Distribution)')

    # Save the plot to a BytesIO object
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()

    # Load the image into a Tkinter-compatible format
    plot_image = Image.open(buf)
    plot_image = ImageTk.PhotoImage(plot_image)

    # Insert the image into the output text box
    output_text.image_create(tk.END, image=plot_image)
    output_text.image = plot_image  # Keep a reference to avoid garbage collection

# ---- 8. GUI Code ----
def start_scan():
    """Starts the web application scan in a separate thread."""
    url = url_entry.get()
    max_depth = int(depth_entry.get())
    max_pages = int(pages_entry.get())

    if not url:
        messagebox.showerror("Error", "Please enter a URL to scan.")
        return

    # Clear the previous output
    output_text.delete("1.0", tk.END)

    # Disable the start button
    start_button.config(state=tk.DISABLED)

    # Reset progress bar
    progress_bar['value'] = 0
    update_progress_bar_color(progress_bar, 0)  # Reset progress bar color

    # Create a session with retry mechanism
    session = create_session()

    # Start the scan in a separate thread to prevent the GUI from freezing
    threading.Thread(target=run_scan, args=(url, max_depth, max_pages, session), daemon=True).start()

def run_scan(url, max_depth, max_pages, session):
    """Runs the web application scan and updates the GUI with the results."""
    try:
        # Crawl and scan the target URL
        vulnerabilities = crawl_and_scan(url, model, vectorizer, session, output_text, progress_bar, max_depth, max_pages)

        # Report and visualize the results
        report_and_visualize(vulnerabilities, output_text)  # Pass output_text to the function

        output_text.insert(tk.END, "✅ Scan completed!\n", "success")
        output_text.see(tk.END)

    except Exception as e:
        error_message = f"[ERROR] An error occurred: {e}\n"
        output_text.insert(tk.END, error_message)  # Error message in plain black text
        output_text.see(tk.END)

    finally:
        # Enable the start button
        start_button.config(state=tk.NORMAL)

def update_progress_bar_color(progress_bar, progress):
    """Updates the progress bar color based on the progress value."""
    if progress < 33:
        progress_bar.configure(style="red.Horizontal.TProgressbar")
    elif progress < 66:
        progress_bar.configure(style="orange.Horizontal.TProgressbar")
    else:
        progress_bar.configure(style="green.Horizontal.TProgressbar")

# Create the main window
root = tk.Tk()
root.title("Web Application Vulnerability Scanner")
root.geometry("1000x700")  # Set a fixed window size

# Apply a modern theme
style = ttk.Style()
style.theme_use("clam")  # Use the 'clam' theme for a modern look

# Configure progress bar styles
style.configure("red.Horizontal.TProgressbar", background="red")
style.configure("orange.Horizontal.TProgressbar", background="orange")
style.configure("green.Horizontal.TProgressbar", background="green")

# Load the background image
bg_image = Image.open("p.jpg")  # Replace with your image path
bg_image = bg_image.resize((1600, 800), Image.Resampling.LANCZOS)
bg_image = ImageTk.PhotoImage(bg_image)

# Create a canvas to place the background image
canvas = tk.Canvas(root, width=1000, height=700)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, image=bg_image, anchor="nw")

# Create a frame for the input fields
input_frame = ttk.Frame(canvas, padding="20")
input_frame.place(relx=0.525, rely=0.1, anchor="ne")  # Adjusted to bring the input box down

# URL Entry
url_label = ttk.Label(input_frame, text="Enter URL to scan:", font=("Helvetica", 12))
url_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
url_entry = ttk.Entry(input_frame, width=50, font=("Helvetica", 12))
url_entry.grid(row=0, column=1, padx=5, pady=5)

# Depth Entry
depth_label = ttk.Label(input_frame, text="Max Crawling Depth:", font=("Helvetica", 12))
depth_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
depth_entry = ttk.Entry(input_frame, width=10, font=("Helvetica", 12))
depth_entry.insert(0, "2")  # Default value
depth_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

# Pages Entry
pages_label = ttk.Label(input_frame, text="Max Pages to Crawl:", font=("Helvetica", 12))
pages_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
pages_entry = ttk.Entry(input_frame, width=10, font=("Helvetica", 12))
pages_entry.insert(0, "100")  # Default value
pages_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

# Start Button
start_button = ttk.Button(input_frame, text="Start Scan", command=start_scan, style="Accent.TButton")
start_button.grid(row=3, column=0, columnspan=2, pady=10)

# Style the Start Button
style.configure("Accent.TButton", font=("Helvetica", 12, "bold"), padding=10, background="#4CAF50", foreground="white")
style.map("Accent.TButton", background=[("active", "#45a049")])

# Progress Bar
progress_bar = ttk.Progressbar(input_frame, orient="horizontal", length=400, mode="determinate", style="red.Horizontal.TProgressbar")
progress_bar.grid(row=4, column=0, columnspan=2, pady=10)

# Output Text Area with Enhanced Styling
output_text = scrolledtext.ScrolledText(
    canvas, 
    width=80, 
    height=20, 
    font=("Helvetica", 12),
    bg="#f0f0f0",  # Light gray background
    fg="#333333",  # Dark gray text color
    insertbackground="#333333",  # Cursor color
    wrap=tk.WORD,  # Wrap text by words
    relief=tk.SUNKEN,  # Sunken border
    borderwidth=2,  # Border width
    padx=10,  # Horizontal padding
    pady=10  # Vertical padding
)
output_text.place(relx=0.550, rely=0.45, anchor="ne")

# Configure tags for different message types
output_text.tag_config("error", foreground="black")  # Error messages in plain black
output_text.tag_config("warning", foreground="orange", font=("Helvetica", 12, "italic"))
output_text.tag_config("success", foreground="green", font=("Helvetica", 12, "bold"))
output_text.tag_config("info", foreground="blue", font=("Helvetica", 12))
output_text.tag_config("vulnerability", foreground="purple", font=("Helvetica", 12, "bold"))

# ---- Start the GUI ----
root.mainloop()