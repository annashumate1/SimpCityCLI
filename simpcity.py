import asyncio
import aiohttp
import logging
import sys
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from yarl import URL
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
import re
import getpass
from pathlib import Path
import json

def load_config() -> dict:
    """
    Loads config from config.json if it exists.
    If not, prompts user for credentials and output folder, then creates config.json.
    """
    import os
    from pathlib import Path

    config_path = Path(__file__).parent / "config.json"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            try:
                config = json.load(f)
                return config
            except json.JSONDecodeError:
                pass
    
    # If config doesn't exist or is invalid, prompt user for info:
    print("No valid config.json found. Let's create one.")
    username = input("Enter SimpCity username: ").strip()
    password = getpass.getpass("Enter SimpCity password (not shown): ").strip()
    output_dir = input("Enter the output directory for downloaded files (default: downloads/simpcity): ").strip()
    if not output_dir:
        output_dir = "downloads/simpcity"

    config = {
        "username": username,
        "password": password,
        "output_dir": output_dir
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    
    print(f"Config saved to {config_path}")
    return config



# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def generate_links(base_link, num_pages):
    links = [base_link.rstrip("/")]
    for page_num in range(2, num_pages + 1):
        new_link = f"{base_link.rstrip('/')}/page-{page_num}"
        links.append(new_link)
    return links


class SimpCityDownloader:
    def __init__(self, username=None, password=None, download_folder=None):
        self.base_url = URL("https://simpcity.su")
        self.session = None
        self.logged_in = False
        self.login_attempts = 0
        self.request_limiter = AsyncLimiter(10, 1)  # 10 requests per second

        if download_folder:
            self.download_path = Path(download_folder)
        else:
            self.download_path = Path("downloads/simpcity")
        self.download_path.mkdir(parents=True, exist_ok=True)

        self.username = username
        self.password = password
        
        # Selectors from original crawler
        self.title_selector = "h1[class=p-title-value]"
        self.posts_selector = "div[class*=message-main]"
        self.post_content_selector = "div[class*=message-userContent]"
        self.images_selector = "img[class*=bbImage]"
        self.videos_selector = "video source"
        self.iframe_selector = "iframe[class=saint-iframe]"
        self.attachments_block_selector = "section[class=message-attachments]"
        self.attachments_selector = "a"
        self.next_page_selector = "a[class*=pageNav-jump--next]"
    
    async def init_session(self):
        """Initialize aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def close(self):
        """Close the session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def check_login_required(self, url: str) -> bool:
        """Check if login is required for the given URL"""
        if self.logged_in:
            return False
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Check for login indicators in the response
                    return 'You must be logged-in to do that.' in text or 'Login or register' in text
                return True  # Assume login required if we can't access the page
        except Exception:
            return True  # Assume login required on error
    
    async def prompt_and_login(self) -> bool:
        """
        If username/password exist (from config), use them directly.
        Otherwise, prompt user for login options.
        """
        if self.username and self.password:
            # We already have credentials from config
            return await self.login(self.username, self.password)

        print("\nLogin required for SimpCity")
        print("1. Login with username/password")
        print("2. Login with xf_user cookie")
        print("3. Continue without login")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            return await self.login(username, password)
            
        elif choice == "2":
            print("\nTo get your xf_user cookie:")
            print("1. Login to SimpCity in your browser")
            print("2. Open Developer Tools (F12)")
            print("3. Go to Application/Storage -> Cookies")
            print("4. Find and copy the 'xf_user' cookie value")
            xf_user = input("\nEnter xf_user cookie value: ").strip()
            return await self.login(None, None, xf_user)
            
        else:
            logger.warning("Continuing without authentication")
            return False

    
    async def verify_login(self) -> bool:
        """Verify if we are actually logged in by checking a profile page"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': str(self.base_url)
        }
        
        try:
            async with self.session.get(self.base_url / "account/account-details", headers=headers) as response:
                if response.status != 200:
                    return False
                
                text = await response.text()
                return 'You must be logged in to view this page.' not in text
        except Exception:
            return False
    
    async def login(self, username: str = None, password: str = None, xf_user_cookie: str = None) -> bool:
        """Login to SimpCity"""
        await self.init_session()
        
        # Common headers for all requests
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'DNT': '1'
        }
        
        if xf_user_cookie:
            self.session.cookie_jar.update_cookies({'xf_user': xf_user_cookie})
            if await self.verify_login():
                self.logged_in = True
                logger.info("Successfully logged in using xf_user cookie")
                return True
            else:
                logger.error("Login failed: Invalid or expired xf_user cookie")
                return False
            
        if not username or not password:
            return False
            
        try:
            # First get the login page to get the token
            login_page_url = self.base_url / "login"
            headers['Referer'] = str(self.base_url)
            
            async with self.session.get(login_page_url, headers=headers) as response:
                if response.status == 403:
                    logger.error("Access forbidden. The site may be blocking automated access.")
                    logger.info("Try using the xf_user cookie method instead.")
                    return False
                elif response.status != 200:
                    logger.error(f"Failed to get login page: {response.status}")
                    return False
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Get CSRF token
                csrf_token = soup.select_one('input[name=_xfToken]')
                if not csrf_token:
                    logger.error("Could not find CSRF token. The login page structure might have changed.")
                    return False
                csrf_token = csrf_token['value']
                
                # Get any hidden fields that might be required
                hidden_fields = {}
                for hidden in soup.find_all('input', type='hidden'):
                    if hidden.get('name') and hidden.get('value'):
                        hidden_fields[hidden['name']] = hidden['value']
            
            # Prepare login data
            login_url = self.base_url / "login/login"
            data = {
                'login': username,
                'password': password,
                '_xfToken': csrf_token,
                '_xfRedirect': str(self.base_url),
                'remember': '1'
            }
            # Add any additional hidden fields
            data.update(hidden_fields)
            
            # Update headers for the login request
            headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': str(self.base_url),
                'Referer': str(login_page_url)
            })
            
            # Attempt login
            async with self.session.post(login_url, data=data, headers=headers, allow_redirects=True) as response:
                if response.status == 403:
                    logger.error("Access forbidden during login. The site may be blocking automated access.")
                    logger.info("Try using the xf_user cookie method instead.")
                    return False
                elif response.status not in [200, 303]:  # 303 is "See Other" redirect after successful login
                    logger.error(f"Login failed: Unexpected status code {response.status}")
                    return False
                
                # Verify login status
                if await self.verify_login():
                    self.logged_in = True
                    logger.info("Successfully logged in")
                    return True
                
                # If verification failed, check the response for error messages
                text = await response.text()
                if any(error in text.lower() for error in ['invalid password', 'invalid username', 'incorrect password']):
                    logger.error("Invalid username or password")
                else:
                    logger.error("Login failed: Could not verify login status")
                return False
                    
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return False
    
    async def get_page(self, url: URL) -> Optional[BeautifulSoup]:
        """Get page content with rate limiting"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Referer': str(self.base_url)
        }
        
        async with self.request_limiter:
            try:
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 403:
                        logger.error(f"Access forbidden for {url}. The site may be blocking automated access.")
                        return None
                    elif response.status != 200:
                        logger.error(f"Failed to get page {url}: {response.status}")
                        return None
                    text = await response.text()
                    return BeautifulSoup(text, 'html.parser')
            except Exception as e:
                logger.error(f"Error getting page {url}: {str(e)}")
                return None
    
    async def download_file(self, url: str, filename: str, subfolder: str = ""):
        """Download a file with progress tracking"""
        save_path = self.download_path / subfolder
        save_path.mkdir(exist_ok=True)
        filepath = save_path / filename
        
        if filepath.exists():
            logger.info(f"File already exists: {filename}")
            return True
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            async with self.request_limiter:
                async with self.session.get(url, headers=headers) as response:
                    if response.status != 200:
                        logger.error(f"Failed to download {filename}: {response.status}")
                        return False
                    
                    file_size = int(response.headers.get('content-length', 0))
                    if file_size == 0:
                        logger.error(f"Empty file: {filename}")
                        return False
                    
                    logger.info(f"Downloading {filename} ({file_size/1024/1024:.1f} MB)")
                    
                    temp_filepath = filepath.with_suffix('.temp')
                    try:
                        with open(temp_filepath, 'wb') as f:
                            downloaded = 0
                            async for chunk in response.content.iter_chunked(8192):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    if file_size:
                                        progress = (downloaded / file_size) * 100
                                        if downloaded % (8192 * 100) == 0:
                                            print(f"\rProgress: {progress:.1f}%", end='', flush=True)
                            
                            print()  # New line after progress
                            
                        temp_filepath.replace(filepath)
                        logger.info(f"Successfully downloaded {filename}")
                        return True
                        
                    except Exception as e:
                        if temp_filepath.exists():
                            temp_filepath.unlink()
                        raise e
                        
        except Exception as e:
            logger.error(f"Error downloading {filename}: {str(e)}")
            if filepath.exists():
                filepath.unlink()
            return False
    
    async def process_post(self, post_content: BeautifulSoup, subfolder: str) -> List[Tuple[str, str]]:
        """Process a forum post and extract media files"""
        files = []
        
        try:
            # Process images
            images = post_content.select(self.images_selector)
            logger.debug(f"Found {len(images)} images in post")
            for img in images:
                src = img.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Process videos
            videos = post_content.select(self.videos_selector)
            logger.debug(f"Found {len(videos)} videos in post")
            for video in videos:
                src = video.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = str(self.base_url / src[1:])
                    filename = src.split('/')[-1]
                    files.append((src, filename))
            
            # Process attachments
            attachments_block = post_content.select_one(self.attachments_block_selector)
            if attachments_block:
                attachments = attachments_block.select(self.attachments_selector)
                logger.debug(f"Found {len(attachments)} attachments in post")
                for attachment in attachments:
                    href = attachment.get('href')
                    if href:
                        if href.startswith('//'):
                            href = 'https:' + href
                        elif href.startswith('/'):
                            href = str(self.base_url / href[1:])
                        filename = href.split('/')[-1]
                        files.append((href, filename))
            
            if files:
                logger.debug(f"Total files found in post: {len(files)}")
            
            return files
            
        except Exception as e:
            logger.error(f"Error processing post: {str(e)}")
            return []
    
    async def process_thread(self, url: str, skip_pagination: bool = False) -> None:
        """Process a forum thread and download all media"""
        logger.info(f"Starting to process thread: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://simpcity.su/{url.lstrip('/')}"
            logger.info(f"Converted URL to: {url}")
        
        thread_url = URL(url)
        current_url = thread_url
        
        page_num = 1

        match = re.search(r'/page-(\d+)', str(thread_url))
        if match:
            page_num = int(match.group(1))
        
        # Check if login is required
        logger.info("Checking if login is required...")
        if await self.check_login_required(str(current_url)):
            if not await self.prompt_and_login():
                logger.error("Login required but authentication failed")
                return
        
        # Create subfolder based on thread title
        logger.info("Fetching thread page...")
        soup = await self.get_page(current_url)
        if not soup:
            logger.error("Failed to get thread page")
            return
            
        title_elem = soup.select_one(self.title_selector)
        if not title_elem:
            logger.error("Could not find thread title")
            return
            
        thread_title = re.sub(r'[<>:"/\\|?*]', '_', title_elem.text.strip())
        logger.info(f"Processing thread: {thread_title}")
        
        
        total_files = 0
        
        while True:
            logger.info(f"Processing page {page_num}")
    
            soup = await self.get_page(current_url)
            if not soup:
                logger.error(f"Failed to get page {page_num}")
                break
            
            # Process each post
            posts = soup.select(self.posts_selector)
            if not posts:
                logger.warning(f"No posts found on page {page_num}")
                break
                
            logger.info(f"Found {len(posts)} posts on page {page_num}")
            
            for post_index, post in enumerate(posts, 1):
                logger.info(f"Processing post {post_index}/{len(posts)} on page {page_num}")
                post_content = post.select_one(self.post_content_selector)
                if post_content:
                    files = await self.process_post(post_content, thread_title)
                    if files:
                        logger.info(f"Found {len(files)} files in post {post_index}")
                        for file_url, filename in files:
                            if await self.download_file(file_url, filename, thread_title):
                                total_files += 1
                else:
                    logger.warning(f"No content found in post {post_index}")
            
            
            
            if skip_pagination:
                logger.info("Skipping auto-pagination (using pre-generated links).")
                break
            else:
                next_page = soup.select_one(self.next_page_selector)
                if next_page and (href := next_page.get('href')):
                    if href.startswith('/'):
                        current_url = self.base_url / href[1:]
                    else:
                        current_url = URL(href)
                    logger.info(f"Moving to page {page_num + 1}: {current_url}")
                    page_num += 1
                else:
                    logger.info("No more pages found")
                    break

        
        if total_files > 0:
            logger.info(f"Thread processing complete. Downloaded {total_files} files.")
        else:
            logger.warning("No files were downloaded from this thread.")

async def main():
    # Load or create config first
    config = load_config()

    # Then create downloader using config credentials
    downloader = SimpCityDownloader(
        username=config.get("username"),
        password=config.get("password"),
        download_folder=config.get("output_dir")
    )

    while True:
        print("\n=== Main Menu ===")
        print("1) Generate links (urls.txt)")
        print("2) Download from all links in urls.txt")
        print("3) Download a single link")
        print("4) Exit")

        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            # Generate URLs
            base_link = input("Enter base link (e.g. https://simpcity.su/threads/XXXX): ").strip()
            num_pages = int(input("Enter the number of pages: ").strip())

            from pathlib import Path
            base_dir = Path(__file__).parent.resolve()
            urls_file = base_dir / "urls.txt"

            all_links = generate_links(base_link, num_pages)
            with open(urls_file, "w", encoding="utf-8") as f:
                for link in all_links:
                    f.write(link + "\n")

            print(f"\nLinks written to {urls_file}")
            # DO NOT return or exit; simply continue back to menu

        elif choice == "2":
            # Download from urls.txt
            from pathlib import Path
            base_dir = Path(__file__).parent.resolve()
            urls_file = base_dir / "urls.txt"
            
            if not urls_file.exists():
                print("urls.txt not found! Please generate links first (option 1).")
                continue

            with open(urls_file, "r", encoding="utf-8") as f:
                links_to_download = [line.strip() for line in f if line.strip()]

            if not links_to_download:
                print("urls.txt is empty! Generate links first.")
                continue

            timeout = 3600  # 1 hour
            try:
                async with asyncio.timeout(timeout):
                    await downloader.init_session()
                    for link in links_to_download:
                        await downloader.process_thread(link, skip_pagination=True)
            except asyncio.TimeoutError:
                logger.error(f"Operation timed out after {timeout} seconds")
            finally:
                logger.info("Cleaning up...")
                await downloader.close()
                logger.info("Done!")
                # Re-create downloader if you plan to keep going:
                downloader = SimpCityDownloader(
                    username=config.get("username"),
                    password=config.get("password"),
                    download_folder=config.get("output_dir")
                )

        elif choice == "3":
            # Download a single link
            single_url = input("Enter the thread URL to download: ").strip()
            if not single_url:
                print("No URL given.")
                continue
            
            timeout = 3600  # 1 hour
            try:
                async with asyncio.timeout(timeout):
                    await downloader.init_session()
                    await downloader.process_thread(single_url)
            except asyncio.TimeoutError:
                logger.error(f"Operation timed out after {timeout} seconds")
            finally:
                logger.info("Cleaning up...")
                await downloader.close()
                logger.info("Done!")
                # Re-create downloader if you plan to keep going:
                downloader = SimpCityDownloader(
                    username=config.get("username"),
                    password=config.get("password"),
                    download_folder=config.get("output_dir")
                )

        elif choice == "4":
            print("Exiting.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nFatal error: {str(e)}")

