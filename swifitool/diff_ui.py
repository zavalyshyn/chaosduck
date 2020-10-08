from tkinter import *
import os


def file_to_hex_col(file):
    """Format the content of a file as a list of hex number (16 per line).

    :param file: path of the file
    :return: a formatted string
    """
    f = open(file, 'rb')
    values = f.read()
    space = 0
    res_str = ''
    for n in range(len(values)):
        value = values[n]
        space += 1
        if space % 16 != 0:
            res_str += "{:02X} ".format(value)
        else:
            res_str += "{:02X}".format(value)
    return res_str


def diff_ui(infile, outfile, fm_list, colors):
    """Open a window comparing the input and output file and highlighting the faults generated.

    :param infile: path of the input file
    :param outfile: path of the output file
    :param fm_list: list of fault models objects applied
    :param colors: color highlighting rules
    :return: nothing (infinite loop until the window is closed)
    """

    def yview(*args):
        text_offset.yview_moveto(args[1])
        text_infile.yview_moveto(args[1])
        text_outfile.yview_moveto(args[1])

    def set_scroll(*args):
        text_offset.yview_moveto(args[0])
        text_infile.yview_moveto(args[0])
        text_outfile.yview_moveto(args[0])
        return scrollbar.set(args[0], args[1])

    # Contents of the window
    root = Tk()
    frame1 = Frame(root)
    frame2 = Frame(root)
    frame3 = Frame(root)

    for k, v in colors.items():
        Label(frame1, text=k, foreground="white", background=v).pack(side=LEFT)
        Label(frame1, text=" ").pack(side=LEFT)
    frame1.pack(anchor=N, fill=Y, expand=False)

    Label(frame2, text='Byte offset' + ' ' * 10 + 'Input file' + ' ' * 83 + 'Output file' + ' ' * 77).pack(side=LEFT)
    frame2.pack(anchor=N, fill=Y, expand=False)

    scrollbar = Scrollbar(frame3)
    Label(frame3, width=1).pack(side=LEFT)
    text_offset = Text(frame3, width=10)
    text_offset.pack(side=LEFT, fill=Y)
    Label(frame3, width=1).pack(side=LEFT)
    text_infile = Text(frame3, width=47)
    text_infile.pack(side=LEFT, fill=Y)
    Label(frame3, width=1).pack(side=LEFT)
    text_outfile = Text(frame3, width=47)
    text_outfile.pack(side=LEFT, fill=Y)
    text_offset.insert(END, '\n'.join("0x{:08X}".format(i) for i in range(0, os.stat(infile).st_size, 16)))
    text_offset['yscrollcommand'] = set_scroll
    text_infile['yscrollcommand'] = set_scroll
    text_outfile['yscrollcommand'] = set_scroll
    Label(frame3, width=1).pack(side=LEFT)
    scrollbar.pack(side=LEFT, fill=Y)
    scrollbar['command'] = yview
    frame3.pack(anchor=N, fill=Y, expand=True)

    text_infile.insert(END, file_to_hex_col(infile))
    text_outfile.insert(END, file_to_hex_col(outfile))

    # Setting the colors
    for f in fm_list:
        for m in f.edited_memory_locations():
            b_start = m // 8
            start = "1." + str(2 * b_start + b_start - b_start // 16)
            stop = "1." + str(2 * b_start + b_start - b_start // 16 + 2)
            text_infile.tag_add(f.name, start, stop)
            text_outfile.tag_add(f.name, start, stop)

    for k, v in colors.items():
        text_infile.tag_config(k, foreground="white", background=v)
        text_outfile.tag_config(k, foreground="white", background=v)

    # Disable edits and configure window
    text_offset.config(state=DISABLED)
    text_infile.config(state=DISABLED)
    text_outfile.config(state=DISABLED)
    root.title('SWIFI Tool')
    root.resizable(False, True)
    root.mainloop()
