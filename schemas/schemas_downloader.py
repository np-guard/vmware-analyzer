from html.parser import HTMLParser
import urllib.request
import sys

parser_schemas = set()

class NSXSchemasParser(HTMLParser):
    def __init__(self, baseurl: str):
        super(NSXSchemasParser, self).__init__()
        self.insideSchema = False
        self.schema = ""
        self.baseurl = baseurl

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.insideSchema = True
        elif tag == "a" and self.insideSchema:
            for attr in attrs:
                if attr[0] == "href":
                    processSchemaFromHtml(self.baseurl+"/" + attr[1])

    def handle_endtag(self, tag):
        if tag == "pre":
            self.insideSchema = False

    def handle_data(self, data):
        if self.insideSchema:
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


def processSchemaFromHtml(url: str):
    print(f'fetching schema from {url}')

    urlParts = url.split('/')
    baseurl = '/'.join(urlParts[:-1])
    schemaName = urlParts[-1]
    schemaName = schemaName[8:-5]  # chopping "schemas_" prefix and ".html" suffix
    if schemaName in parser_schemas:
        print(f'schema {schemaName} was already parsed')
        return
    parser_schemas.add(schemaName)

    parser = NSXSchemasParser(baseurl=baseurl)
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        html = response.read().decode("ISO-8859-1")
        parser.feed(html)

    if parser.schema == "":
        print("No schema found")
        return

    parser.fix_schema()

    with open(schemaName, 'w') as outScheme:
        outScheme.write(parser.schema)

if __name__ == "__main__":
    sys.exit(processSchemaFromHtml(sys.argv[1]))
