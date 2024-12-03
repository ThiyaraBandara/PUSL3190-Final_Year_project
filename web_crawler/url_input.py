# url_input.py

class URLInput:
    def __init__(self):
        self.urls = []

    def get_urls(self):
        print("Enter URLs (type 'done' to finish):")
        while True:
            url = input("URL: ")
            if url.lower() == 'done':
                break
            if url:  # Ensure the URL is not empty
                # TODO: Validate the URL format before appending
                self.urls.append(url)
        return self.urls