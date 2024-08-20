

from html.parser import HTMLParser
import urllib.request
import sys

parsed_schemas = set()

class NSXSchemasParser(HTMLParser):
    def __init__(self, baseurl: str):
        super(NSXSchemasParser, self).__init__()
        self.inside_schema = False
        self.schema = ""
        self.baseurl = baseurl

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.inside_schema = True
        elif tag == "a" and self.inside_schema:
            for attr in attrs:
                if attr[0] == "href":
                    process_schema_from_url(self.baseurl+"/" + attr[1])

    def handle_endtag(self, tag):
        if tag == "pre":
            self.inside_schema = False

    def handle_data(self, data):
        if self.inside_schema:
            self.schema += data

    def fix_schema(self):
        lines = ""
        for line in self.schema.splitlines():
            if line.find('"required"') != -1: # required tag is not used according to schema standard, and doesn't interest us
                continue
            if line.find("$ref") != -1:  # for some reason the html misses a closing '"' for $ref values
                if line.endswith(", "):
                    line = line.replace(',', '",')
                else:
                    line += '"'
            
            line = line.replace('"int"', '"integer"')  # type is sometimes wrongly set to "int" instead of "integer"

            lines += line + '\n'

        self.schema = lines


def process_schema_from_url(url: str):
    print(f'fetching schema from {url}')

    url_parts = url.split('/')
    baseurl = '/'.join(url_parts[:-1])
    schema_name = url_parts[-1]
    schema_name = schema_name[8:-5]  # chopping "schemas_" prefix and ".html" suffix
    if schema_name in parsed_schemas:
        return  # already parsed
    parsed_schemas.add(schema_name)

    parser = NSXSchemasParser(baseurl=baseurl)
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        html = response.read().decode("ISO-8859-1")
        parser.feed(html)

    if parser.schema == "":
        print("No schema found")
        return

    parser.fix_schema()

    with open(schema_name + '.json', 'w') as outScheme:
        outScheme.write(parser.schema)

if __name__ == "__main__":
    with open(sys.argv[1]) as schemas_file:
        for schema in schemas_file:
            schema = schema.strip()
            url = f'https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/schemas_{schema}.html'
            process_schema_from_url(url)
