from fpdf import FPDF
import os


class PDF(FPDF):
    font_title = 'Arial'
    font_ch_title = 'helvetica'

    def header(self):
        self.set_font(self.font_title, 'B', 15)
        w = self.get_string_width("Benshmarck Windows 2012 server R2") + 6
        self.set_x((210 - w) / 2)
        self.cell(w, 9, 'Benshmarck Windows 2012 server R2', 1, 1, align='C')
        self.ln(10)

    # Page Footer

    def footer(self):
        # Set position off the foooter
        self.set_y(-15)
        self.set_font(self.font_title, 'I', 8)
        # Set font color grey
        self.set_text_color(169)
        # Page number
        self.cell(
            0, 10, f'Page {self.page_no()}/{self.alias_nb_pages()}', align='C')

    def chapter_title(self, ch_num, ch_title, link=None):
        # set link location
        self.set_link(link)

        self.set_font(self.font_ch_title, '', 12)
        self.set_fill_color(200, 220, 255)
        chapter_title = f'Chapter {ch_num} : {ch_title}'
        self.cell(0, 5, chapter_title, ln=1, fill=1)
        self.ln()

    # Chapter content
    def chapter_body(self, name):
        # read text file
        with open(name, 'rb') as fh:
            txt = fh.read().decode('latin-1', 'ignore')

        # set font
        self.set_font('times', '', 12)
        # insert text
        self.multi_cell(0, 5, txt)
        # line break
        self.ln()

    def print_chapte(self, ch_num, ch_title, content, link=None):       
        self.add_page()
        self.chapter_title(ch_num, ch_title, link)
        self.chapter_body(content)


if __name__ == "__main__":

    # Init Template PDF
    pdf = PDF('P', 'mm', 'letter')

    # metadata
    pdf.set_title("Audit Server")
    pdf.set_author("jahleel Lacascade")


    # Sommain PDF
    pdf.add_page()

    ## Link Sommain
    ch_auth = pdf.add_link()
    ch_network = pdf.add_link()
    ch_system = pdf.add_link()
    ch_encrypte = pdf.add_link()
    ch_logging = pdf.add_link()
    ch_update = pdf.add_link()
    ch_security = pdf.add_link()
    ch_specific_point = pdf.add_link()
    ch_system_security = pdf.add_link()
    ch_complementary_element = pdf.add_link()

    ## Attack Link
    pdf.cell(0,15,'Sommain', ln=1)
    pdf.cell(0,10,'1 Authentication', ln=1, link=ch_auth)
    pdf.cell(0,10,'2 Network access controls', ln=1, link=ch_network)
    pdf.cell(0,10,'3 System access controls', ln=1, link=ch_system)
    pdf.cell(0,10,'4 Encrypte', ln=1, link=ch_encrypte)
    pdf.cell(0,10,'5 Logging', ln=1, link=ch_logging)
    pdf.cell(0,10,'6 Updates', ln=1, link=ch_update)
    pdf.cell(0,10,'7 Security strategies', ln=1, link=ch_security)
    pdf.cell(0,10,'8 Specific points', ln=1, link=ch_specific_point)
    pdf.cell(0,10,'9 System security', ln=1, link=ch_system_security)
    pdf.cell(0,10,'10 Complementary elements', ln=1, link=ch_complementary_element)


    # Content PDF
    pdf.print_chapte(1,'Authentication', os.path.join('output', 'authentication.txt'), ch_auth)
    pdf.print_chapte(2,'Network access controls', os.path.join('output', 'network.txt'), ch_network)
    pdf.print_chapte(3,'System access controls', os.path.join('output', 'system.txt'), ch_system)
    pdf.print_chapte(4,'Encrypte', os.path.join('output', 'encrypte.txt'), ch_encrypte)
    pdf.print_chapte(5,'Logging', os.path.join('output', 'logging.txt'), ch_logging)
    pdf.print_chapte(6,'Updates', os.path.join('output', 'updates_windows.txt'), ch_update) 
    pdf.print_chapte(7,'Security strategies', os.path.join('output', 'security_strategie.txt'), ch_security)
    pdf.print_chapte(8,'Specific points', os.path.join('output', 'specific_point.txt'), ch_specific_point)
    pdf.print_chapte(9,'System security', os.path.join('output', 'system_secure.txt'), ch_system_security)
    pdf.print_chapte(10,'Complementary elements', os.path.join('output', 'complementary_element.txt'), ch_complementary_element)


    # Output generator file PDF
    pdf.output(os.path.join('..', '..', 'AuditGenerate', 'Audit.pdf'))
