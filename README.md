# SimpCityCLI (Fork)

This is a **fork** of the excellent [SimpCityCLI](https://github.com/Emy69/SimpCityCLI) project. The goal of this fork is to add some extra features and quality-of-life improvements for automated downloading from SimpCity.su.

## Original Repository

- **Original Author**: [Emy69](https://github.com/Emy69)
- **Original Repo**: [github.com/Emy69/SimpCityCLI](https://github.com/Emy69/SimpCityCLI)

---

## What’s New in This Fork?

Below are the major changes I’ve introduced in this fork:

1. **`generate_links` Function & `urls.txt`**  
   - I added a function `generate_links(base_link, num_pages)` that constructs thread URLs for each page (e.g. `page-1`, `page-2`, etc.).  
   - The generated links are written to a `urls.txt` file in the root directory of the project.  
   - Users can specify a base thread URL (like `https://simpcity.su/threads/some-thread.1234`) and the number of pages, and all resulting URLs automatically go into `urls.txt`.

2. **Improved Main Menu Flow**  
   - **Menu Options**:
     1. **Generate Links**: Prompts for a base URL and page count, writes them to `urls.txt`.  
     2. **Download from `urls.txt`**: Reads all URLs from `urls.txt` and downloads them one by one.  
     3. **Download a Single Link**: For quick single-thread downloads.  
     4. **Exit**: Terminates the program.  
   - This means you can generate URLs, then immediately choose to download them without restarting the script.

3. **`config.json` for Credentials & Output Directory**  
   - I introduced a `config.json` that stores:
     - **Username**  
     - **Password**  
     - **Download output directory**  
   - If `config.json` does not exist, the program prompts you for these details, saves them, and reuses them for all subsequent runs.  
   - This way, you don’t have to re-enter your login credentials on every run or every page, and the tool can auto-login once per session.

4. **Auto-Login Once**  
   - It now loads your **username/password** from `config.json` and attempt to log in **once**.  
   - If you have valid credentials, the code will skip interactive login prompts and avoid repeated login checks for every page.

5. **Skipping Pagination When Using Pre-Generated Links**  
   - If you generate multiple pages manually with `urls.txt`, the code **won’t** also follow the forum’s “next page” link.  
   - This prevents exceeding your chosen number of pages and avoids downloading the same pages multiple times.  
   - It accomplishes this with an extra argument `skip_pagination=True` passed to the downloader if its reading from `urls.txt`.

---

## How to Use (Fork Version)

1. **Clone Fork**
   ```bash
   git clone https://github.com/annashumate1/SimpCityCLI/
   ```
2. **Navigate Into Fork Directory**
   ```bash
   cd SimpCityCLI
   ```

3. **Install Requirements**  
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Script**  
   ```bash
   python simpcity.py
   ```
5. **Config Setup**  
   - On first run, if `config.json` is missing, you’ll be asked for:
     - SimpCity username and password
     - Desired output directory  
   - These get saved to `config.json`, which the script will reuse automatically.

6. **Menu-Driven Flow**  
   - **Generate Links**: Choose option **1** to create `urls.txt`.  
   - **Download Links**: Option **2** reads `urls.txt` and downloads each page.  
   - **Download Single Thread**: Option **3** if you just want to process a single URL without writing to `urls.txt`.  
   - **Exit**: Option **4** ends the script.

---

## Credits

- **Base Project**: [Emy69/SimpCityCLI](https://github.com/Emy69/SimpCityCLI)  
- **Fork Maintainer**: [Anna](https://github.com/annashumate1)

This fork is released under the same license as the original project (check the original repository for license information). Feel free to open issues or pull requests in this fork for any bug fixes or enhancements.



By using this fork you agree that Anna is beautiful and deserves every ounce of respect you have


Everything added was built and tested in Arch Linux btw
