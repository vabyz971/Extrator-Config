import os
from fpdf import FPDF

class CIS:
    def __init__(self):

        self.PDF = pdf
        self.Manifest()

    def Manifest(self):
        self.name = "Benshmarck Windows 2012 server R2"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.1"
        self.url_CIS_benchmark = "https://www.cisecurity.org/wp-content/uploads/2017/04/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.0.pdf"

        #Génération du PDF
        self.PDF.set_title(self.name)
        self.PDF.cell(15, 5, 'Manifest')

        # Interface Line Command
        print("\n")
        print("=" * 4, "Manifest", "=" * 3)
        print("Name   ", ":", self.name)
        print("Author ", ":", self.author)
        print("Email  ", ":", self.email)
        print("Version", ":", self.version)
        print("CIS Benshmarck", ":", self.url_CIS_benchmark)


class GeneratePDF(FPDF):

    # Page En tête
    def header(self):
        self.set_font('helvetica', 'B', 20)
        self.cell(0, 10, 'Benshmarck Windows 2012 server R2', border=False, ln=1, align='C')

    # Page Footer
    def footer(self):
        # Set position off the foooter
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        # Set font color grey
        self.set_text_color(169)
        # Page number
        self.cell(0, 10, f'Page {self.page_no()}/{self.alias_nb_pages()}', align='C')


if __name__ == "__main__":

    # Template du PDF
    pdf = GeneratePDF()

    # Ajout de la première page
    pdf.add_page()

    win2012R2 = CIS()

    # Sorti du PDF
    pdf.output(os.path.join('..', '..', 'AuditGenerate', win2012R2.name + '.pdf'))
