import tkinter as tk
import pwn
import re

class DrawingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tassellatura poligoni")
        self.canvas = tk.Canvas(self.root, bg="black")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Button-1>", self.on_canvas_click_sx)
        self.canvas.bind("<Button-3>", self.on_canvas_click_dx)
        self.vertices = []
        self.current_line = None
        self.done = False;

    def on_canvas_click_sx(self, event):
        if(self.done):
            self.clear_canvas()
            self.vertices = []
            self.done = False
        x, y = event.x, event.y
        self.vertices.append((x, y))
        self.draw_vertex(x, y)
        if len(self.vertices) > 1:
            self.draw_line(self.vertices[-2], self.vertices[-1])

    def on_canvas_click_dx(self, event):
        x, y = event.x, event.y
        if len(self.vertices) > 1:
            self.draw_line(self.vertices[0], self.vertices[-1])
        self.current_line = None
        self.done = True
        sendPolygon(self.vertices, self)

    def draw_vertex(self, x, y):
        size = 5
        self.canvas.create_oval(x - size, y - size, x + size, y + size, fill="white")

    def draw_line(self, start, end):
        x1, y1 = start
        x2, y2 = end
        self.current_line = self.canvas.create_line(x1, y1, x2, y2, fill="white")

    def clear_canvas(self):
        self.canvas.delete("all")  # Rimuovi tutti gli oggetti dalla canvas
        self.vertices = []  # Rimuovi tutti i vertici

def sendPolygon(polygon, app):
    exe = pwn.ELF("./program")
    r = pwn.process([exe.path])

    r.sendafter(": ",str(len(polygon)).encode() + b"\n")

    a = 1
    for x,y in polygon:
        r.sendafter(str(a).encode() + b": "  ,b"(" + str(x).encode() + b";" +  str(y).encode() + b")\n")
        a = a + 1 
    
    previous = None
    first = None
    try:
        while True:
            for t in re.findall(r"\([0-9]+;[0-9]+\)",r.recvline().decode("ascii")):
                coords = re.findall(r"[0-9]+",t)
                if first == None:
                    first = coords
                if previous != None:
                    app.draw_line(previous, (coords[0], coords[1]))
                    print("drawing ")
                    print(coords)
                previous =  (coords[0], coords[1])
            app.draw_line(previous, first)
    except :
        print("end")

    r.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = DrawingApp(root)
    root.mainloop()