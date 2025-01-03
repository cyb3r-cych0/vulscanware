import threading
from tkinter import messagebox
from bs4 import BeautifulSoup  # parse HTML
from urllib.parse import urljoin  # convert relative URLs to full URLs
import _tkinter
import customtkinter  # external module built on top of tkinter
import requests  # send get requests on the internet
import re  # uses pythex to search strings in a bigger string
import sqlite3  # python database
import exceptiongroup
import time

print("VSW Started...")

# configure app appearance
customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

# configure app window
root = customtkinter.CTk()
root.title("VulScanWare")
root.geometry("1100x580")

# configure app grid layout
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure([2, 3], weight=0)
root.grid_rowconfigure((0, 1, 2), weight=1)

# Create a database or connect to one & # Create cursor (executes commands)
con = sqlite3.connect("scanned.db")
cur = con.cursor()

# Create table and name it | Doc strings to write sqlite3 code | (designate columns & data types (5))
query_1 = """CREATE TABLE IF NOT EXISTS crawled (
    link_address text
    )"""
query_2 = """CREATE TABLE IF NOT EXISTS scanned (
    weak_link text
    )"""
query_3 = """CREATE TABLE IF NOT EXISTS injected (
    weak_sqlink text
    )"""
cur.execute(query_1)
cur.execute(query_2)
cur.execute(query_3)
print("Tables Created...")

# globals
global text_box
global target_links
global target_url


# main
def run_program():
    # create a database or connect to one & cursor | create a variable and pass name of database
    con = sqlite3.connect("scanned.db")
    cur = con.cursor()

    target_url = entry.get()
    target_links = []

    # getting started
    if entry.get():
        main_button_1.configure(fg_color="green", border_width=1, text="Running...", state="disabled")
        text = "\t\t*** Crawler Started ***\n\n[+] Crawling Target " + str(entry.get()) + "\n"
        text_box.delete("0.0", "end")
        text_box.insert("end", text)

    start_time = time.time()

    '''methods to run crawler & scanner on target
    create method that can be passed a URL and return all links that can be found in this URL
    Discovering paths, subdomains and directories
    Goal -> Recursively list all links from base URL'''

    # <-- Implementing methods to discover vulnerabilities -->
    def test_xss_in_link(url):
        xss_test_script = b"<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + str(xss_test_script))
        response = requests.get(url)
        return xss_test_script in response.content

    def test_xss_in_form(form, url):
        xss_test_script = b"<sCript>alert('test')</scriPt>"
        response = submit_form(form, xss_test_script, url)
        return xss_test_script in response.content
    
    # method to scan for sqli ini forms ***
    # def test_sqli_in_form(form, url):
    #     sql_test_script = b"1 or 1=1"  # UNION SELECT user, password FROM users#
    #     response = submit_form(form, sql_test_script, url)
    #     return sql_test_script in response.content

    # extract forms
    def get_forms(url):
        response = requests.get(url).content
        parsed_html = BeautifulSoup(response, features="lxml")  # Parse HTML file using beautiful soup
        return parsed_html.findAll("form")

    # submit forms
    def submit_form(form, value, url):
        action = form.get("action")  # extract action attribute | relative url
        post_url = urljoin(url, action)  # full url, starts with domain name and has proper path
        method = form.get("method")  # extract method attribute
        input_list = form.findAll("input")  # loop through inputs & for each input, extract attributes
        post_data = {}  # create post_data dict
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")  # set default input value
            if input_type == "text":  # type text input check
                input_value = value
            post_data[input_name] = input_value  # set input_name as key & input_value as value for this dict

        # submit form
        if method == "post":
            return requests.post(post_url, data=post_data)
        return requests.get(post_url, params=post_data)

    # extract links
    def extract_links_from(url):
        try:
            try:
                # Filtering and extracting useful data from response
                response = requests.get(url)
                return re.findall('href="(.*?)"', str(response.content))  # using regex to find links on pythex |
            except requests.exceptions.MissingSchema:
                error = "Invalid URL.'HTTP/HTTPS Not Found!'"
                customtkinter.CTkLabel(root, text=error).grid(row=4, column=3, padx=(10, 10), pady=(10, 10),
                                                              sticky="nsew")
                pass
        except requests.exceptions.ConnectionError:
            pass

    # function to run crawler program & save crawler data to database
    def crawl(url):
        href_links = extract_links_from(url)
        # handling type error if href_links is empty
        try:
            for link in href_links:
                link = urljoin(url, link)  # convert relative URLs to full URLs
                # Extracting unique links and storing them in a list
                if "#" in link:  # remove anchor from HTML links
                    link = link.split("#")[0]
                if target_url in link and link not in target_links:  # remove links out of scope(internal links) | remove duplicates
                    target_links.append(link)

                    # display on app progress
                    customtkinter.CTkLabel(root, text="Links Found >> " + str(len(target_links))).grid(row=4, column=3,
                                                                                                       padx=(10, 10),
                                                                                                       pady=(10, 10),
                                                                                                       sticky="nsew")

                    # dump links on entry box and save them to database
                    for item in target_links:
                        # do some processing with item
                        entry.delete(0, "end")
                        entry.insert("end", item)

                        # insert links into table | structured query language
                        cur.execute("INSERT INTO crawled VALUES (:link_address)",
                                    # python dict. key = dv | value = entry box
                                    {
                                        "link_address": entry.get()
                                    }
                                    )

                        # progress bar effects
                        progressbar_1.step()
                        root.update_idletasks()
                        progressbar_1.update()
                        root.update()
                        slider_progressbar_frame.update()
                        slider_progressbar_frame.update_idletasks()
                        # clear entry box
                        entry.delete(0, "end")

                    # Recursively discovering links and Handling Recursion error
                    try:
                        crawl(link)  # method calling itself to map whole website | recursive method
                    except RecursionError:
                        pass
        except TypeError:
            pass

    crawl(target_url)

    end_time = time.time()

    # Crawling & Scanning Process Info
    if len(target_links) > 0:
        display = "[+] Links Found: " + str(len(target_links)) + " \n"
        time_var = f"\n[+] Time Elapsed: {end_time - start_time:.2f} seconds.\n"
        text_box.delete("1.0", "end")
        text_box.insert("end", "\t\t*** CRAWL COMPLETE ***\n\n[+] Target Crawled: " + str(target_url))
        text_box.insert("end", time_var)
        text_box.insert("end", display)
        main_button_1.configure(fg_color="transparent", border_width=1, text="Run",
                                state="enabled")  # Reconfigure button
        time.sleep(2)

        # check
        run_scanner = messagebox.askyesno("VULSCANWARE", "Crawl Complete. Scan Now..?")
        if run_scanner == 1:
            text_box.insert("end", "\n\nStarting Scanner...\n\n")

            # scanner module
            def run_scanner():
                main_button_1.configure(fg_color="green", border_width=1, text="Running...", state="disabled")
                customtkinter.CTkLabel(root, text="Scanning for XSS...").grid(row=4, column=3, padx=(10, 10),
                                                                              pady=(10, 10), sticky="nsew")
                text_box.delete("0.0", "end")
                start_time1 = time.time()

                for link in target_links:  # iterate over all target links
                    forms = get_forms(link)  # extract forms in each link
                    # test form in each link
                    for form in forms:
                        text_box.insert("end", "[+] Testing form in ~ " + link + "\n")
                        # call method to discover xss vulnerability in forms
                        is_vulnerable_to_xss = test_xss_in_form(form, link)
                        if is_vulnerable_to_xss:
                            entry.insert("end", "[*XSS*] *** " + link + " ***")
            
                        # method to scan for SQLI vulnerability ***
                        # is_vulnerable_to_sqli = test_sqli_in_form(form, link)
                        # if is_vulnerable_to_sqli:
                        #     entry.insert("end", "[*SQLI*] *** " + link + " ***")
                        #     cur.execute("INSERT INTO injected VALUES (:weak_sqlink)",
                        #                 {
                        #                     "weak_sqlink": entry.get()
                        #                 }
                        #                 )

                    # display on app effects
                    progressbar_1.configure(mode="determinate")
                    progressbar_1.step()
                    root.update_idletasks()
                    root.update()
                    progressbar_1.update()
                    slider_progressbar_frame.update()
                    slider_progressbar_frame.update_idletasks()
                    entry.delete(0, "end")

                    # check for get request in url
                    if "=" in link:
                        text_box.insert("end", "[+] Testing link ~ " + link + "\n")
                        # call method to discover vulnerability in links
                        is_vulnerable_to_xss = test_xss_in_link(link)
                        if is_vulnerable_to_xss:
                            entry.insert("end", "[*XSS*] *** " + link + " ***")
                            cur.execute("INSERT INTO scanned VALUES (:weak_link)",
                                        {
                                            "weak_link": entry.get()
                                        }
                                        )

                    # display on app effects
                    progressbar_1.configure(mode="determinate")
                    progressbar_1.step()
                    root.update_idletasks()
                    root.update()
                    progressbar_1.update()
                    slider_progressbar_frame.update()
                    slider_progressbar_frame.update_idletasks()
                    entry.delete(0, "end")

                messagebox.showinfo("VULSCANWARE", "Scan Completed Successful.")
                end_time1 = time.time()
                main_button_1.configure(fg_color="transparent", border_width=1, text="Run", state="enabled")
                time_elapsed = f"\nTime Elapsed: {end_time1 - start_time1:.2f} seconds.\n"
                customtkinter.CTkLabel(root, text=time_elapsed).grid(row=4, column=3, padx=(10, 10),
                                                                     pady=(10, 10), sticky="nsew")

            run_scanner()
        else:
            print("Scanner Cancelled")
            text_box.insert("end", "\n[+] Scanner Cancelled. \n[+] Terminating Process...\n")
            progressbar_1.configure(mode="indeterminate")
            progressbar_1.start()
            progressbar_1.stop()

    else:
        text_box.delete("1.0", "end")
        text_box.insert("end", "\t\t*** NO DATA TO DISPLAY ***\n\n")
        display = "[+] Links Found: " + str(len(target_links)) + " \n"
        time_var = f"[+] Time Elapsed: {end_time - start_time:.2f} seconds.\n"
        text_box.insert("end", "[+] Target : " + str(target_url) + "\n")
        text_box.insert("end", time_var)
        text_box.insert("end", display)

    # Commit changes & Close connection
    con.commit()
    con.close()


# function to query report from database
def db_report():
    print("Crawler DB Button pressed")

    top = customtkinter.CTkToplevel()
    top.title("Scanner Database")
    top.geometry("850x390")
    top.configure(fg_color="black")

    def exit_toplevel():
        # auto_database
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        cur.execute("DELETE FROM crawled")
        cur.execute("DELETE FROM scanned")
        cur.execute("DELETE FROM injected")
        print("Rows Deleted...")
        con.commit()
        con.close()
        top.destroy()

    def pull_data():
        # Create a database or connect to one & Create cursor (executes commands)
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        # Query the DB using the SELECT command | select unique value from DB
        cur.execute("SELECT DISTINCT (link_address) FROM crawled")
        links = cur.fetchall()  # fetchone, fetchmany(50)

        # Loop through records & display them on our app
        print_records = ""  # create parameter|variable. set it to nothing since we are in a function
        for link in links:
            print_records += "[+] " + str(
                link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak

        # create query textbox to display records
        textbox.delete("0.0", "end")
        textbox.insert("end", "\t\t*** CRAWLED LINKS ***\n\n" + print_records)

        # Commit changes & Close connection
        con.commit()
        con.close()

    def pull_data_2():
        # Create a database or connect to one & Create cursor (executes commands)
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        # Query the DB using the SELECT command | select unique value from DB
        cur.execute("SELECT DISTINCT (weak_link) FROM scanned")
        links = cur.fetchall()  # fetchone, fetchmany(50)

        # Loop through records & display them on our app
        print_records = ""  # create parameter|variable. set it to nothing since we are in a function
        for link in links:
            print_records += "[+] " + str(
                link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak

        # create query textbox to display records
        textbox.delete("0.0", "end")
        textbox.insert("end", "\t\t*** VULNERABLE LINKS ***\n\n" + print_records)

        # Commit changes & Close connection
        con.commit()
        con.close()

    # SQLI INJECTION DB QUERY
    # def pull_data_3():
    #     # Create a database or connect to one & Create cursor (executes commands)
    #     con = sqlite3.connect("scanned.db")
    #     cur = con.cursor()

    #     # Query the DB using the SELECT command | select unique value from DB
    #     cur.execute("SELECT DISTINCT (weak_sqlink) FROM injected")
    #     links = cur.fetchall()  # fetchone, fetchmany(50)

    #     # Loop through records & display them on our app
    #     print_records = ""  # create parameter|variable. set it to nothing since we are in a function
    #     for link in links:
    #         print_records += "[+] " + str(
    #             link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak

    #     # create query textbox to display records
    #     textbox.delete("0.0", "end")
    #     textbox.insert("end", "\t\t*** VULNERABLE SQLINKS ***\n\n" + print_records)

    #     # Commit changes & Close connection
    #     con.commit()
    #     con.close()

    # toplevel frame and widgets
    top_frame = customtkinter.CTkFrame(top, fg_color="transparent", width=700, height=300)
    top_frame.grid(row=0, column=0, columnspan=1, padx=(20, 10), pady=(20, 10), sticky="nsew")

    textbox = customtkinter.CTkTextbox(top_frame, width=600, height=300)
    textbox.grid(row=1, column=0, columnspan=1, padx=(10, 10), pady=(10, 10), sticky="nsew")

    top_sidebar_frame = customtkinter.CTkFrame(top, width=140, corner_radius=5)
    top_sidebar_frame.grid(row=0, column=1, rowspan=5, padx=10, pady=10, sticky="nsew")
    top_sidebar_frame.grid_rowconfigure(5, weight=1)
    top_sidebar_frame.grid_columnconfigure(1, weight=1)

    top_logo_label = customtkinter.CTkLabel(top_sidebar_frame, text="DataBase",
                                            font=customtkinter.CTkFont(size=20, weight="bold"))
    top_logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
    top_sidebar_button_1 = customtkinter.CTkButton(top_sidebar_frame, text="Site Map", command=pull_data)
    top_sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
    top_sidebar_button_2 = customtkinter.CTkButton(top_sidebar_frame, text="Detected XSS", command=pull_data_2)
    top_sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
    # top_sidebar_button_4 = customtkinter.CTkButton(top_sidebar_frame, text="Detected SQLI", command=pull_data_3)
    # top_sidebar_button_4.grid(row=3, column=0, padx=20, pady=10)
    top_sidebar_button_3 = customtkinter.CTkButton(top_sidebar_frame, text="Quit", command=exit_toplevel)
    top_sidebar_button_3.grid(row=5, column=0, padx=20, pady=10)


# function for sidebar button 1
def sidebar_button_event_1():
    print("Button 1 Pressed")
    entry.configure(state="normal")
    sidebar_button_2.configure(state="enabled")
    progressbar_1.start()
    text_box.delete("1.0", "end")
    text_box.insert("end",
                    "\t\t*** VULSCANWARE ***\n\n[+] Getting Started with common Vulnerabilities.\n[+] Starting XSS program... \n[+]Starting SQLI program...\n \n[+] Please enter Target Link in the entry box below and press Run.")
    customtkinter.CTkLabel(root, text="indexing...").grid(row=4, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")


# function for side button 2
def sidebar_button_event_2():
    global p_thread
    print("Button 2 Pressed")
    progressbar_1.stop()
    text_box.delete("1.0", "end")
    text_box.insert("end",
                    "\t\t*** VULSCANWARE ***\n\n[+] Terminating all processes...\n[+] Stopping XSS program... \n[+] Stopping SQLI program...")
    customtkinter.CTkLabel(root, text="stopping...").grid(row=4, column=3, padx=(10, 10),
                                                          pady=(10, 10), sticky="nsew")
    # if hasattr(root, 'thread') and p_thread.is_alive():
    #     p_thread.do_run = False  # set flag to stop the thread
    #     p_thread.join()  # wait for thread to finish


# function for quit button
def quit_button_event():
    print("Quit Button Pressed")
    response = messagebox.askyesno("VulScanWare", "Exit Program...?")
    if response == 1:
        # auto_database
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute("DROP TABLE IF EXISTS crawled")
            cur.execute("DROP TABLE IF EXISTS scanned")
            cur.execute("DROP TABLE IF EXISTS injected")
        except sqlite3.OperationalError:
            print(sqlite3.OperationalError)
            pass
        print("Tables Dropped...")
        con.commit()
        con.close()
        root.destroy()
        print("Program terminated")
    else:
        pass


# function to change appearance
def change_appearance_mode_event(new_appearance_mode: str):
    customtkinter.set_appearance_mode(new_appearance_mode)


# function to change scale
def change_scaling_event(new_scaling: str):
    new_scaling_float = int(new_scaling.replace("%", "")) / 100
    customtkinter.set_widget_scaling(new_scaling_float)


# Build App
try:
    # sidebar frame with widgets
    sidebar_frame = customtkinter.CTkFrame(root, width=140, corner_radius=0)
    sidebar_frame.grid(row=0, column=0, rowspan=5, sticky="nsew")
    sidebar_frame.grid_rowconfigure(5, weight=1)

    logo_label = customtkinter.CTkLabel(sidebar_frame, text="V S W",
                                        font=customtkinter.CTkFont(size=25, weight="bold"))
    logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
    sidebar_button_1 = customtkinter.CTkButton(sidebar_frame, text="Start Scanner", command=sidebar_button_event_1)
    sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
    sidebar_button_2 = customtkinter.CTkButton(sidebar_frame, text="Stop Scanner", fg_color="dark red",
                                               command=sidebar_button_event_2)
    sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
    sidebar_button_3 = customtkinter.CTkButton(sidebar_frame, text="Quit", command=quit_button_event)
    sidebar_button_3.grid(row=9, column=0, padx=20, pady=10)
    appearance_mode_label = customtkinter.CTkLabel(sidebar_frame, text="Appearance Mode:", anchor="w")
    appearance_mode_label.grid(row=5, column=0, padx=20, pady=(40, 0))
    appearance_mode_optionemenu = customtkinter.CTkOptionMenu(sidebar_frame, values=["Light", "Dark", "System"],
                                                              command=change_appearance_mode_event)
    appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))
    scaling_label = customtkinter.CTkLabel(sidebar_frame, text="UI Scaling:", anchor="w")
    scaling_label.grid(row=7, column=0, padx=20, pady=(10, 0))
    scaling_optionemenu = customtkinter.CTkOptionMenu(sidebar_frame, values=["80%", "90%", "100%", "110%", "120%"],
                                                      command=change_scaling_event)
    scaling_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

    # main frame and widgets
    text_box = customtkinter.CTkTextbox(master=root, width=300, height=400)
    text_box.grid(row=0, column=1, padx=(10, 10), pady=(20, 10), sticky="nsew")
    text_box.configure(font=customtkinter.CTkFont(size=30, weight="normal"))

    # entry and run buttons
    entry = customtkinter.CTkEntry(root, placeholder_text="Enter Target Link")
    entry.grid(row=3, column=1, columnspan=2, padx=(20, 10), pady=(20, 10), sticky="nsew")
    main_button_1 = customtkinter.CTkButton(master=root, text="Run", command=run_program,
                                            fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
    main_button_1.grid(row=3, column=3, padx=(20, 10), pady=(20, 10), sticky="nsew")

    # tabview
    tabview = customtkinter.CTkTabview(root, width=220, height=250)
    tabview.grid(row=0, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")
    tabview.add("DB Report")
    tabview.tab("DB Report").grid_columnconfigure(0, weight=1)  # configure grid of individual tabs

    string_input_button = customtkinter.CTkButton(tabview.tab("DB Report"), text="Query", command=db_report)
    string_input_button.grid(row=3, column=0, padx=20, pady=(10, 10))

    label_scanner = customtkinter.CTkLabel(tabview.tab("DB Report"), text="Scanner Report")
    label_scanner.grid(row=0, column=0, padx=20, pady=20)

    # slider and progressbar frame
    slider_progressbar_frame = customtkinter.CTkFrame(root, fg_color="transparent")
    slider_progressbar_frame.grid(row=1, column=1, columnspan=2, padx=(20, 0), pady=(20, 0), sticky="nsew")
    slider_progressbar_frame.grid_columnconfigure(2, weight=1)
    slider_progressbar_frame.grid_rowconfigure(4, weight=1)
    progressbar_1 = customtkinter.CTkProgressBar(slider_progressbar_frame, width=100)
    progressbar_1.grid(row=1, column=1, columnspan=2, padx=(20, 10), pady=(20, 10), sticky="ew")
    main_text_lbl = customtkinter.CTkLabel(root, text="On App Updates: ")
    main_text_lbl.grid(row=4, column=1, padx=(5, 5), pady=(10, 10), sticky="nsew")

    # set default values
    appearance_mode_optionemenu.set("Dark")
    scaling_optionemenu.set("100%")
    text_box.insert("end",
                    "\t\t*** VULSCANWARE ***\n\n[+] Press the side button to start scanner...\n")
    text_box.configure(font=customtkinter.CTkFont(size=13))
    entry.configure(state="disabled")
    sidebar_button_2.configure(state="disabled")
    progressbar_1.configure(mode="indeterminate")

    # Commit changes & Close connection
    con.commit()
    con.close()

    # Create an event loop
    root.mainloop()

except _tkinter.TclError:
    exceptiongroup.print_exc()
    print("An Error Occurred!")
    pass
