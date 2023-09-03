import tkinter as tk
import pwn
import re
import shapely
import time
from shapely.geometry import LineString


failedPolygons = []

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

        window_width = 800
        window_height = 600
        self.root.geometry(f"{window_width}x{window_height}")
        self.root.resizable(width=False, height=False)

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

        sendPolygon(self)

    def draw_vertex(self, x, y):
        size = 5
        self.canvas.create_oval(x - size, y - size, x + size, y + size, fill="white")

    def draw_line(self, start, end, fill="white"):
        x1, y1 = start
        x2, y2 = end
        self.current_line = self.canvas.create_line(x1, y1, x2, y2, fill=fill)

    def clear_canvas(self):
        self.canvas.delete("all")  # Rimuovi tutti gli oggetti dalla canvas
        self.vertices = []  # Rimuovi tutti i vertici

def has_intersection(triangles):
    # Lista per tenere traccia dei lati dei triangoli
    sides = []

    # Estrai i lati da ciascun triangolo e aggiungili alla lista
    for triangle in triangles:
        for i in range(len(triangle)):
            side = LineString([triangle[i], triangle[(i + 1) % 3]])
            sides.append(side)

    # Controlla se almeno un lato interseca un altro lato (e non sono lo stesso segmento)
    for i in range(len(sides)):
        for j in range(i + 1, len(sides)):
            if sides[i] != sides[j]:
                # Estrai gli estremi dei due segmenti
                p1, p2 = sides[i].coords
                q1, q2 = sides[j].coords
                
                # Verifica se gli estremi dei due segmenti non coincidono
                if p1 != q1 and p1 != q2 and p2 != q1 and p2 != q2:
                    if sides[i].intersects(sides[j]):
                        return True
    
    # Nessuna intersezione trovata
    return False


def sendPolygon(app):
    exe = pwn.ELF("../out/program")
    

    polygon = []
    with open("./polygons", "r") as file:
        r = pwn.process([exe.path])
        for line in file:
            coordinate_pattern = r'\b(\d+\.\d+),(\d+\.\d+)\b'
            coordinate_matches = re.findall(coordinate_pattern, line)
            polygon = [(round(float(x) - 644047,2)/2,  round(-(float(y)  - 5494382),2)/2) for x, y in coordinate_matches][0:-1]


            r.sendafter(": ",str(len(polygon)).encode() + b"\n")

            a = 1
            for x,y in polygon:
                r.sendafter(str(a).encode() + b": "  ,b"(" + str(x).encode() + b";" +  str(y).encode() + b")\n")
                a = a + 1 

            poly = shapely.Polygon([[a,b] for a,b in polygon])
            #print(poly)
            triangulatedArea = 0
            triangles = []
            previous = None
            first = None
            try:
                data = r.recvline().decode("ascii")
                while "end" not in data:
                    triangle = []
                    for t in re.findall(r"\([-?\d.]+;[-?\d.]+\)",data):
                        coords = re.findall(r"[-?\d.]+",t)
                        triangle.append([float(coords[0]), float(coords[1])])
                        if first == None:
                            x,y = coords
                            first = (x,y)
                        if previous != None:
                            app.draw_line(previous, (float(coords[0]), float(coords[1])))
                        previous =  (coords[0],  float(coords[1]))
                    app.draw_line(previous, first)
                    previous = None
                    first = None
                    triangulatedArea +=  shapely.Polygon(triangle).area
                    #print(triangle)
                    triangles.append(triangle)
                    data = r.recvline().decode("ascii")
                if abs(poly.area - triangulatedArea) > 0.05 * poly.area : raise ValueError("area not equal " + str(poly.area) + " " + str(triangulatedArea))
                if(has_intersection(triangles)) : raise ValueError("Edge intersection ")
            except Exception as error:
                print("Error :", error)
                failedPolygons.append(polygon)
                r.close()
                r = pwn.process([exe.path])
        r.close()
    printFailedPolygon(app)


def printFailedPolygon(app):
    print("---------- Failed Polygons ---------")
    for polygon in failedPolygons:
        old = None
        for x,y in polygon+polygon[0:1]:
            print("("+str(x) + ";" + str(y)+")", end="")
            if old == None:
                old = (float(x),float(y))
            else:
                app.draw_line(old, (float(x), float(y)),"red")
                old = (float(x),float(y))
        print()
        print(" ---------- ")

if __name__ == "__main__":
    root = tk.Tk()
    app = DrawingApp(root)
    root.mainloop()