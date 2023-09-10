import tkinter as tk
import pwn
import re
from shapely.geometry import LineString, Point




def sendPolygon(polygon, app):
    exe = pwn.ELF("../out/program")
    r = pwn.process([exe.path])

    r.sendafter(": ",str(len(polygon)).encode() + b"\n")

    print("Polygon: ", end="")
    a = 1
    for x,y in polygon:
        y = app.canvas.winfo_reqheight() - y
        r.sendafter(str(a).encode() + b": "  ,b"(" + str(x).encode() + b";" +  str(y).encode() + b")\n")
        print("("+str(x) + ";" + str(y)+")", end="")
        a = a + 1 
    print()
    
    previous = None
    first = None
    try:
        while True:
            print("drawing ")
            #print(r.recvline())
            for t in re.findall(r"\([0-9,-]+;[0-9,-]+\)",r.recvline().decode("ascii")):
                coords = re.findall(r"[0-9,-]+",t)
                if first == None:
                    x,y = coords
                    first = (x,app.canvas.winfo_reqheight()  - int(y))
                if previous != None:
                    app.draw_line(previous, (coords[0], app.canvas.winfo_reqheight() - int(coords[1])))
                    print(coords, end="")
                previous =  (coords[0],  app.canvas.winfo_reqheight() - int(coords[1]))
            app.draw_line(previous, first)
            print(coords, end="")
            previous = None
            first = None
            print()
    except Exception as error:
        print("Error :", error)

    r.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = DrawingApp(root, sendPolygon)
    root.mainloop()