import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import itertools
import threading
import math
import string
import hashlib
import requests
import re

# Налаштування
GUESSES_PER_SECOND = 1_000_000_000
HASH_FILE = r"D:\password_check\rockyou.txt.sha1.txt"
PATTERN_FILE = r"D:\password_check\patterns.txt"

#Завантаження хешу
def load_hashes(filepath):
    hashes = set()
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            h = line.strip().split(":")[0]
            hashes.add(h)
    return hashes
HASHES = None

# Мутації
def generate_mutations(password, max_leet=4):
    replacements = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1'],
        'o': ['0'],
        's': ['$', '5'],
        'l': ['1']    }

    base_variants = {
        password,
        password.lower(),
        password.capitalize()    }
    mutations = set(base_variants)

    for base in base_variants:
        base_lower = base.lower()
        positions = [
            (i, replacements[ch])
            for i, ch in enumerate(base_lower)
            if ch in replacements   ]
    
    for r in range(1, min(len(positions), max_leet) + 1):
            for combo in itertools.combinations(positions, r):
                for subs in itertools.product(*[c[1] for c in combo]):
                    mutated = list(base)
                    for (pos, _), sub in zip(combo, subs):
                        mutated[pos] = sub
                    mutations.add("".join(mutated))
                    
    suffixes = ["1", "12", "123", "!", "!1", "@"]
    prefixes = ["!", "@"]
    final = set()
    for m in mutations:
        for p in prefixes:
            for s in suffixes:
                final.add(p +m +s)

    return final

def check_mutations_hash(password):
    if HASHES is None:
        return None, None

    for variant in generate_mutations(password):
        sha1 = hashlib.sha1(variant.encode()).hexdigest().upper()
        if sha1 in HASHES:
            return True, variant

    return False, None

# Шаблони
def check_patterns(password):
    if re.search(r"(.)\1{2,}", password):
        return "Повторювані символи"

    for i in range(len(password) - 2):
        if ord(password[i+1]) == ord(password[i]) + 1 and \
           ord(password[i+2]) == ord(password[i+1]) + 1:
            return "Послідовність символів"

    try:
        with open(PATTERN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().lower() in password.lower():
                    return "Клавіатурний шаблон"
    except FileNotFoundError:
        return "Файл шаблонів не знайдено"

    return None

# Перевірка на злив
def check_hibp(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"User-Agent": "PasswordAnalyzer"}
        )
        if r.status_code != 200:
            return False, 0

        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
    except requests.RequestException:
        pass

    return False, 0

# Аналіз
def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)
    return len(password) * math.log2(charset) if charset else 0

def strength(entropy):
    if entropy < 28: return "Дуже слабкий"
    if entropy < 36: return "Слабкий"
    if entropy < 60: return "Середній"
    if entropy < 128: return "Сильний"
    return "Дуже сильний"

# Політики
def policy_check(password):
    errors = []
    if len(password) < 12: errors.append("Довжина <12 символів")
    if not any(c.isupper() for c in password): errors.append("Немає великих літер")
    if not any(c.islower() for c in password): errors.append("Немає малих літер")
    if not any(c.isdigit() for c in password): errors.append("Немає цифр")
    if not any(c in string.punctuation for c in password): errors.append("Немає спецсимволів")
    return errors

#Орієнтовний час для злому
def time_to_crack_bruteforce(entropy, speed):
    return math.pow(2, entropy) / speed

def format_time(seconds):
    if seconds < 1:
        return "менше секунди"

    units = [
        ("років", 60*60*24*365),
        ("днів", 60*60*24),
        ("годин", 60*60),
        ("хвилин", 60),
        ("секунд", 1) ]
    for name, unit in units:
        if seconds >= unit:
            return f"{seconds/unit:.2f} {name}"
    return "невідомо"

# Аналіз
def analyze():
    pwd = entry.get()
    if not pwd:
        messagebox.showwarning("Помилка", "Введіть пароль")
        return

    output.config(state="normal")
    output.delete(1.0, tk.END)

    mutated, variant = check_mutations_hash(pwd)
    if mutated:
        output.insert(tk.END, f"Мутація знайдена: {variant}\n")
    elif mutated is None:
        output.insert(tk.END, "Неможливо перевірити мутації\n")
    else:
        output.insert(tk.END, "Мутації не знайдено\n")

    pattern = check_patterns(pwd)
    if pattern:
        output.insert(tk.END, f"Шаблон: {pattern}\n")

    for err in policy_check(pwd):
        output.insert(tk.END, f"Порушення політик: {err}\n")

    entropy = calculate_entropy(pwd)
    output.insert(tk.END, f"Ентропія: {entropy:.2f} біт\n")
    output.insert(tk.END, f"Стійкість: {strength(entropy)}\n")

    seconds = time_to_crack_bruteforce(entropy, GUESSES_PER_SECOND)
    output.insert(tk.END, f"Brute-force: {format_time(seconds)}\n")

    pwned, count = check_hibp(pwd)
    if pwned:
        output.insert(tk.END, f"HIBP: злитий {count} разів\n")
    else:
        output.insert(tk.END, "HIBP: не знайдено\n")

    bar['value'] = min(entropy / 128 * 100, 100)
    output.config(state="disabled")


#GUI
try:
    HASHES = load_hashes(HASH_FILE)
except FileNotFoundError:
    HASHES = None

root = tk.Tk()
root.title("Криптоаналіз паролів")
root.geometry("520x400")

ttk.Label(root, text="Введіть пароль:", font=("Times New Roman", 14)).pack(pady=5)
entry = tk.Entry(root, show="*", width=40, font=("Times New Roman", 14))
entry.pack()

def toggle():
    entry.config(show="" if entry.cget("show") else "*")

tk.Button(root, text="Показати / Сховати", command=toggle).pack(pady=3)

bar = ttk.Progressbar(root, length=300, maximum=100)
bar.pack(pady=5)

tk.Button(root, text="Перевірити", command=lambda: threading.Thread(target=analyze).start()).pack(pady=10)

output = tk.Text(root, height=12, width=55, state="disabled")
output.pack()

root.mainloop()
