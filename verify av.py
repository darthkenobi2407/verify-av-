import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import hashlib
import requests

key = 'your_virustotal_api_key'


def msg(label, text):
    label.config(text='')
    for char in text:
        label.config(text=label['text'] + char)
        label.update()
        label.after(100)
    label.config(text=text)


def gethash(path):
    h = hashlib.sha256()

    with open(path, 'rb') as file:
        while True:
            data = file.read(1024 * 1024)

            if not data:
                break

            h.update(data)

    return h.hexdigest()


def scan():
    path = filedialog.askopenfilename()

    if not path:
        return

    output.config(text='')
    msg(output, 'calculating hash')

    try:
        filehash = gethash(path)

        output.config(text='')
        msg(output, 'checking virustotal')

        headers = {
            'x-apikey': key
        }

        url = 'https://www.virustotal.com/api/v3/files/{}'.format(filehash)
        res = requests.get(url, headers=headers, timeout=15)

        if res.status_code == 200:
            data = res.json()
            stats = data['data']['attributes']['last_analysis_stats']

            bad = stats.get('malicious', 0)
            sus = stats.get('suspicious', 0)
            safe = stats.get('harmless', 0)
            unknown = stats.get('undetected', 0)

            output.config(text='')

            if bad > 0:
                msg(
                    output,
                    'threat detected\n\nmalicious {}\nsuspicious {}\nharmless {}\nundetected {}'.format(
                        bad,
                        sus,
                        safe,
                        unknown
                    )
                )

            elif sus > 0:
                msg(
                    output,
                    'suspicious file\n\nmalicious {}\nsuspicious {}\nharmless {}\nundetected {}'.format(
                        bad,
                        sus,
                        safe,
                        unknown
                    )
                )

            else:
                msg(
                    output,
                    'no threats detected\n\nmalicious {}\nsuspicious {}\nharmless {}\nundetected {}'.format(
                        bad,
                        sus,
                        safe,
                        unknown
                    )
                )

        elif res.status_code == 404:
            output.config(text='')
            msg(
                output,
                'file not found in virustotal\n\nsha256\n{}'.format(filehash)
            )

        elif res.status_code == 401:
            output.config(text='')
            msg(output, 'invalid virustotal api key')

        elif res.status_code == 429:
            output.config(text='')
            msg(output, 'virustotal api limit reached')

        else:
            output.config(text='')
            msg(output, 'virustotal error {}'.format(res.status_code))

    except Exception as e:
        output.config(text='')
        msg(output, 'error\n{}'.format(e))


def home():
    output.config(text='')
    msg(output, 'proceeding')

    name = simpledialog.askstring('Name', 'What is your name?')

    output.config(text='')
    options.config(text='')

    homebtn.pack_forget()
    probtn.pack_forget()

    msg(output, 'Verify AV')
    msg(output, 'Greetings {}!'.format(name))

    showoptions()


def pro():
    output.config(text='')
    msg(output, 'Charge = ₹2500/year')

    name = simpledialog.askstring('Name', 'What is your name?')

    output.config(text='')
    options.config(text='')

    homebtn.pack_forget()
    probtn.pack_forget()

    msg(output, 'Verify AV')
    msg(output, 'Greetings {}!'.format(name))

    showoptions()


def showoptions():
    options.config(text='What may I do for you?')

    scanbtn.pack()
    accountbtn.pack()
    firewallbtn.pack()
    devicebtn.pack()


root = tk.Tk()
root.title('Verify AV')
root.configure(bg='dark slate gray')

width = 400
height = 300

screenw = root.winfo_screenwidth()
screenh = root.winfo_screenheight()

x = (screenw // 2) - (width // 2)
y = (screenh // 2) - (height // 2)

root.geometry(f'{width}x{height}+{x}+{y}')
root.resizable(False, False)
root.attributes('-alpha', 0.95)

frame = tk.Frame(
    root,
    bg='dark slate gray',
    padx=20,
    pady=20,
    relief=tk.RIDGE,
    bd=5
)

frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

output = tk.Label(
    frame,
    font=('Helvetica', 14),
    justify='center',
    bg='dark slate gray',
    fg='white'
)

output.pack(pady=10)

title = tk.Label(
    frame,
    text='Verify AV',
    font=('Helvetica', 20),
    justify='center',
    bg='dark slate gray',
    fg='white'
)

title.pack()

buttons = tk.Frame(frame, bg='dark slate gray')
buttons.pack(pady=10)

homebtn = tk.Button(
    buttons,
    text='Home',
    width=10,
    height=2,
    command=home,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

homebtn.pack(side=tk.LEFT, padx=5)

probtn = tk.Button(
    buttons,
    text='Pro',
    width=10,
    height=2,
    command=pro,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

probtn.pack(side=tk.LEFT, padx=5)

options = tk.Label(
    frame,
    text='',
    font=('Helvetica', 14),
    justify='center',
    bg='dark slate gray',
    fg='white'
)

scanbtn = tk.Button(
    frame,
    text='Virus Scan',
    width=15,
    height=2,
    command=scan,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

accountbtn = tk.Button(
    frame,
    text='Account Protection',
    width=15,
    height=2,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

firewallbtn = tk.Button(
    frame,
    text='Firewall',
    width=15,
    height=2,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

devicebtn = tk.Button(
    frame,
    text='Device Security',
    width=15,
    height=2,
    relief=tk.GROOVE,
    bd=2,
    bg='dark gray',
    fg='white'
)

root.mainloop()
