import tkinter as tk

class DrawingApp:
    def __init__(self, root, end_function = None ):
        self.root = root
        self.root.title("Tassellatura poligoni")
        self.canvas = tk.Canvas(self.root, bg="black")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Button-1>", self.on_canvas_click_sx)
        self.canvas.bind("<Button-3>", self.on_canvas_click_dx)
        self.vertices = []
        self.current_line = None
        self.done = False;
        self.end_function = end_function

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
        x, y = event.x, event.y
        if len(self.vertices) > 1:
            self.draw_line(self.vertices[0], self.vertices[-1])
        self.current_line = None
        self.done = True
        if(self.end_function != None):
            self.end_function(self.vertices, self)

    def draw_vertex(self, x, y):
        size = 5
        self.canvas.create_oval(x - size, y - size, x + size, y + size, fill="white")

    def draw_line(self, start, end, color="white"):
        x1, y1 = start
        x2, y2 = end
        self.current_line = self.canvas.create_line(x1, y1, x2, y2, fill=color)

    def clear_canvas(self):
        self.canvas.delete("all")  
        self.vertices = []  