import tkinter as tk
from tkinter import font, messagebox
import requests

# Function to get the public IP address (IPv4 or IPv6)
def get_ip(ip_version='v4'):
    try:
        if ip_version == 'v4':
            response = requests.get('https://api.ipify.org?format=json')
        elif ip_version == 'v6':
            response = requests.get('https://api64.ipify.org?format=json')
        else:
            return f"Invalid IP version: {ip_version}"

        response.raise_for_status()  # Check for request errors
        return response.json()["ip"]
    except requests.RequestException as e:
        return f"Error fetching {ip_version.upper()} address: {e}"

# Function to get location data based on IP address (IPv4 or IPv6)
def get_location(ip):
    try:
        # Replace with your own IP API key if required
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        response.raise_for_status()  # Check for request errors
        location_data = response.json()

        location_info = {
            "ip": ip,
            "city": location_data.get("city", "N/A"),
            "region": location_data.get("region", "N/A"),
            "country": location_data.get("country_name", "N/A"),
            "postal": location_data.get("postal", "N/A"),
            "isp": location_data.get("org", "N/A"),
            "asn": location_data.get("asn", "N/A"),
            "latitude": location_data.get("latitude", "N/A"),
            "longitude": location_data.get("longitude", "N/A"),
            "timezone": location_data.get("timezone", "N/A"),
            "calling_code": location_data.get("country_calling_code", "N/A"),
            "currency": location_data.get("currency", "N/A"),
        }
        return location_info
    except requests.RequestException as e:
        return f"Error fetching location data for {ip}: {e}"

# Function to update the GUI with the IP and Location info
def update_ip_info(ip_version):
    ip = get_ip(ip_version)  # Get IP address (IPv4 or IPv6)
    ip_location = get_location(ip)  # Get geolocation data for the IP

    if isinstance(ip_location, dict):
        # Update each box with specific information
        ip_text_widget.config(state=tk.NORMAL)
        ip_text_widget.delete(1.0, tk.END)
        ip_text_widget.insert(tk.END, ip_location['ip'])
        ip_text_widget.config(state=tk.DISABLED)

        city_text_widget.config(state=tk.NORMAL)
        city_text_widget.delete(1.0, tk.END)
        city_text_widget.insert(tk.END, ip_location['city'])
        city_text_widget.config(state=tk.DISABLED)

        region_text_widget.config(state=tk.NORMAL)
        region_text_widget.delete(1.0, tk.END)
        region_text_widget.insert(tk.END, ip_location['region'])
        region_text_widget.config(state=tk.DISABLED)

        country_text_widget.config(state=tk.NORMAL)
        country_text_widget.delete(1.0, tk.END)
        country_text_widget.insert(tk.END, ip_location['country'])
        country_text_widget.config(state=tk.DISABLED)

        postal_text_widget.config(state=tk.NORMAL)
        postal_text_widget.delete(1.0, tk.END)
        postal_text_widget.insert(tk.END, ip_location['postal'])
        postal_text_widget.config(state=tk.DISABLED)

        isp_text_widget.config(state=tk.NORMAL)
        isp_text_widget.delete(1.0, tk.END)
        isp_text_widget.insert(tk.END, ip_location['isp'])
        isp_text_widget.config(state=tk.DISABLED)

        asn_text_widget.config(state=tk.NORMAL)
        asn_text_widget.delete(1.0, tk.END)
        asn_text_widget.insert(tk.END, ip_location['asn'])
        asn_text_widget.config(state=tk.DISABLED)

        latitude_text_widget.config(state=tk.NORMAL)
        latitude_text_widget.delete(1.0, tk.END)
        latitude_text_widget.insert(tk.END, ip_location['latitude'])
        latitude_text_widget.config(state=tk.DISABLED)

        longitude_text_widget.config(state=tk.NORMAL)
        longitude_text_widget.delete(1.0, tk.END)
        longitude_text_widget.insert(tk.END, ip_location['longitude'])
        longitude_text_widget.config(state=tk.DISABLED)

        timezone_text_widget.config(state=tk.NORMAL)
        timezone_text_widget.delete(1.0, tk.END)
        timezone_text_widget.insert(tk.END, ip_location['timezone'])
        timezone_text_widget.config(state=tk.DISABLED)

        calling_code_text_widget.config(state=tk.NORMAL)
        calling_code_text_widget.delete(1.0, tk.END)
        calling_code_text_widget.insert(tk.END, ip_location['calling_code'])
        calling_code_text_widget.config(state=tk.DISABLED)

        currency_text_widget.config(state=tk.NORMAL)
        currency_text_widget.delete(1.0, tk.END)
        currency_text_widget.insert(tk.END, ip_location['currency'])
        currency_text_widget.config(state=tk.DISABLED)
    else:
        ip_text_widget.insert(tk.END, ip_location)

# Login function to verify user credentials
def login():
    username = username_entry.get()
    password = password_entry.get()

    if username == "admin" and password == "admin":  # Example credentials
        messagebox.showinfo("Login Successful", "Welcome!")
        login_frame.pack_forget()
        main_frame.pack(fill=tk.BOTH, expand=True)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Create the main window
root = tk.Tk()
root.title("IP Address & Location Finder - Team 27")

# Set the window size
root.geometry("600x750")
root.config(bg="#2c3e50")

# Custom fonts
title_font = font.Font(family="Helvetica", size=16, weight="bold")
label_font = font.Font(family="Arial", size=14)
button_font = font.Font(family="Arial", size=14, weight="bold")
footer_font = font.Font(family="Arial", size=14, weight="bold")

# Create a login frame
login_frame = tk.Frame(root, bg="#2c3e50")
login_frame.pack(fill=tk.BOTH, expand=True)

# Login form elements
username_label = tk.Label(login_frame, text="Username:", font=label_font, bg="#2c3e50", fg="#ecf0f1")
username_label.pack(pady=(100, 5))
username_entry = tk.Entry(login_frame, font=label_font)
username_entry.pack(pady=5)

password_label = tk.Label(login_frame, text="Password:", font=label_font, bg="#2c3e50", fg="#ecf0f1")
password_label.pack(pady=5)
password_entry = tk.Entry(login_frame, font=label_font, show="*")
password_entry.pack(pady=5)

login_button = tk.Button(login_frame, text="Login", font=button_font, bg="#3498db", fg="#ffffff", command=login)
login_button.pack(pady=20)

# Main frame (hidden until login is successful)
main_frame = tk.Frame(root, bg="#2c3e50")

# Display title and Team label
team_label = tk.Label(main_frame, text="Team 27", font=footer_font, fg="#ecf0f1", bg="#2c3e50")
team_label.pack(side=tk.TOP, pady=20)

title_label = tk.Label(main_frame, text="Public IP & Location Finder", font=title_font, fg="#ecf0f1", bg="#2c3e50")
title_label.pack(pady=10)

# Create frames for each data field
def create_text_widget(label_text):
    frame = tk.Frame(main_frame, bg="#2c3e50")
    frame.pack(fill=tk.X, padx=20, pady=2)
    label = tk.Label(frame, text=label_text, font=label_font, fg="#ecf0f1", bg="#2c3e50")
    label.pack(side=tk.LEFT)
    text_widget = tk.Text(frame, height=1, width=40, font=label_font, fg="#ecf0f1", bg="#34495e", state=tk.DISABLED)
    text_widget.pack(side=tk.RIGHT)
    return text_widget

# Create text widgets for each piece of information
ip_text_widget = create_text_widget("IP Address:")
city_text_widget = create_text_widget("City:")
region_text_widget = create_text_widget("Region:")
country_text_widget = create_text_widget("Country:")
postal_text_widget = create_text_widget("Postal Code:")
isp_text_widget = create_text_widget("ISP:")
asn_text_widget = create_text_widget("ASN:")
latitude_text_widget = create_text_widget("Latitude:")
longitude_text_widget = create_text_widget("Longitude:")
timezone_text_widget = create_text_widget("Timezone:")
calling_code_text_widget = create_text_widget("Calling Code:")
currency_text_widget = create_text_widget("Currency:")

# Button to fetch IP info
fetch_ipv4_button = tk.Button(main_frame, text="Get IPv4/IPv6 Info", font=button_font, bg="#3498db", fg="#ffffff", relief="flat", command=lambda: update_ip_info('v4'))
fetch_ipv4_button.pack(pady=20, fill=tk.X)

# Run the Tkinter event loop
root.mainloop()
