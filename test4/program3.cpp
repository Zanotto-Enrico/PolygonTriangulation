#include <vector>
#include <utility>
#include <iostream>
#include <math.h>
#include <algorithm>
#include <set>
#include <queue>
#include <stack>
#include <utility>
#include <list>
#include <map>

/*                        ^
*                         |0
*                         |
*  10                * * *|* * 
*          * * * * *      | *
*           *             | 
*            *          * |
*              *          | *
*  5          *           |    *   
*            *            |        * 
*           *             |           *
*          ***            |              *
*  1          * * * * * * * * * * * * * * * * 
*                         |
*                         |6 
*          1       5        10        15     
*/

struct Coord
{
  double x;
  double y;
  double z;
  size_t index;
    // Comparison operator for sorting vertices based on x-coordinate.
    bool operator<(const Coord& other) const
    {
        return x < other.x;
    }

    bool operator==(const Coord& other) const 
    {
        return x == other.x &&  y == other.y && z == other.z;
    }

};



struct Triangle {
    Coord p1;
    Coord p2;
    Coord p3;
};

struct mySegment {
    Coord p1;
    Coord p2;
};


Coord crossProduct(const Coord& v1, const Coord& v2) {
    Coord result;
    result.x = v1.y * v2.z - v1.z * v2.y;
    result.y = v1.z * v2.x - v1.x * v2.z;
    result.z = v1.x * v2.y - v1.y * v2.x;
    return result;
}

// Funzione per calcolare il prodotto scalare tra due vettori
double dotProduct(const Coord& v1, const Coord& v2) {
    return v1.x * v2.x + v1.y * v2.y + v1.z * v2.z;
}

// Funzione per calcolare la lunghezza di un vettore
double vectorLength(const Coord& vector) {
    return std::sqrt(vector.x * vector.x + vector.y * vector.y + vector.z * vector.z);
}

// Funzione per calcolare l'intersezione tra un mySegmento e un triangolo in 3 dimensioni
double intersectmySegmentTriangle(const mySegment& mySegment, const Triangle& triangle) {
    Coord edge1, edge2, mySegmentVector, h, s, q;
    double a, f, u, v, t;

    edge1.x = triangle.p2.x - triangle.p1.x;
    edge1.y = triangle.p2.y - triangle.p1.y;
    edge1.z = triangle.p2.z - triangle.p1.z;

    edge2.x = triangle.p3.x - triangle.p1.x;
    edge2.y = triangle.p3.y - triangle.p1.y;
    edge2.z = triangle.p3.z - triangle.p1.z;

    mySegmentVector.x = mySegment.p2.x - mySegment.p1.x;
    mySegmentVector.y = mySegment.p2.y - mySegment.p1.y;
    mySegmentVector.z = mySegment.p2.z - mySegment.p1.z;

    // vettore normale del piano generato dal vettore del segmento e di un lato del triangolo
    h = crossProduct(mySegmentVector, edge2);
    // prodotto scalare tra la normale e un altro lato del triangolo
    a = dotProduct(edge1, h);
    // se il prodotto scalare è molto vicino allo zero allora il vettore è parallelo al triangolo
    if (a > -0.00001 && a < 0.00001) {
        return -1; 
    }


    f = 1 / a;
    s.x = mySegment.p1.x - triangle.p1.x;
    s.y = mySegment.p1.y - triangle.p1.y;
    s.z = mySegment.p1.z - triangle.p1.z;

    // prima coordinata baricentrica
    u = f * dotProduct(s, h);

    if (u < 0 || u > 1) {
        return -1; // L'intersezione si trova fuori 
    }

    q = crossProduct(s, edge1);
    // seconda coordinata baricentrica
    v = f * dotProduct(mySegmentVector, q);

    if (v < 0 || u + v > 1) {
        return -1; // L'intersezione si trova fuori 
    }

    t = f * dotProduct(edge2, q);

    if (t > 0 && t < 1) {
        return t; // L'intersezione si trova all'interno 
    }

    return -1; // L'intersezione si trova fuori 
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Edge
{
public:
    Coord start;
    Coord end;
    Coord* helper; // sweep line helper vertex

    Edge(const Coord& vertex1, const Coord& vertex2) {
        if (vertex1.x < vertex2.x) {
            start = vertex1;
            end = vertex2;
        } else {
            start = vertex2;
            end = vertex1;
        }
        helper = new Coord();
    }
    Edge(const Coord& vertex1, const Coord& vertex2, const Coord& help) : Edge(vertex1,vertex2) 
    {    
        helper = new Coord(help);
    }

    // Comparison operator for sorting edge events based on y-coordinate.
    bool operator<(const Edge& other) const
    {
        if(start.y == other.start.y)
            if( start.x == other.start.x)
                if( end.y == other.end.y)
                    end.x < other.end.x;
                else
                    return end.y < other.end.y;
            else
                return start.x < other.start.x;
        return start.y < other.start.y;
    }
    bool operator==(const Edge& other) const {
        return start == other.start && end == other.end;
    }
    bool operator!=(const Edge& other) const {
        return !(*this == other);
    }
    

};

// Calculate arc length between two indices in a cyclic array
int arc_length(int i, int j, int N) {
    return std::min(std::abs(i - j), N - std::abs(i - j));
}

struct LessPredicate {
    int N; // Number of vertices in the polygon
    LessPredicate(int numVertices) : N(numVertices) {}

    bool operator()(const Edge& diag1, const Edge& diag2) const {
        int arcLenDiag1 = arc_length(diag1.start.index, diag1.end.index, N);
        int arcLenDiag2 = arc_length(diag2.start.index, diag2.end.index, N);
        return arcLenDiag1 < arcLenDiag2;
    }
};

std::vector<std::vector<Coord>> subdividePolygon(const std::vector<Coord>& perimeter, const std::vector<Edge>& diagonals) {
    int numVertices = static_cast<int>(perimeter.size());
    LessPredicate lessPredicate(numVertices);

    std::vector<Edge> sortedDiagonals = diagonals;
    std::sort(sortedDiagonals.begin(), sortedDiagonals.end(), lessPredicate);

    std::vector<std::vector<Coord>> subPolygons;
    std::vector<bool> diagonalUsed(perimeter.size(), false);
    
    std::vector<Coord> startingVertices;
    startingVertices.push_back(perimeter[0]);

    while (!startingVertices.empty()) {

        std::vector<Coord> subPolygon;
        Coord current = *(startingVertices.end()-1);
        startingVertices.pop_back();

        int end = current.index;
        bool diagonalTaken = true;
        do {
            subPolygon.push_back(current);
            if(!diagonalTaken)
                for (const Edge& diagonal : diagonals) {
                    if (diagonal.start.index == current.index) {
                        if(!diagonalUsed[current.index])
                            startingVertices.push_back(current);
                        diagonalUsed[current.index] = diagonalUsed[diagonal.end.index] = true;
                        current = diagonal.end;
                        diagonalTaken = true;
                        break;
                    } else if (diagonal.end.index == current.index ) {
                        if(!diagonalUsed[current.index])
                            startingVertices.push_back(current);
                        diagonalUsed[current.index] = diagonalUsed[diagonal.start.index] = true;
                        current = diagonal.start;
                        diagonalTaken = true;
                        break;
                    }
                }
            else
                diagonalTaken = false;
            if(!diagonalTaken)
                current = perimeter[(current.index+1)%perimeter.size()];
                
            
        } while (current.index != end);

        subPolygons.push_back(subPolygon);
    }


    return subPolygons;
}



// finds the first edge over a given point
const Edge* findUpperBound(double y,double x, std::set<Edge> bounds)
{
    std::set<Edge>::iterator it = bounds.end();    // can be improved
    if (it != bounds.begin()) {
        --it;  // Move to the previous edge
        if (y < it->start.y + ((it->end.y - it->start.y) / (it->end.x - it->start.x)) * (x - it->start.x)) {
            return &(*it);
        }
    }

    return nullptr;  // Return a default Edge if not found
}

/*
    sweep line algorithm to partition non monoton polygons in monotone polygons
*/
std::vector<std::vector<Coord>> partitionPolygonIntoMonotone(std::vector<Coord>& polygon)
{
    for (size_t i = 0; i < polygon.size(); ++i)
    {
        polygon[i].index = i;
    }
    int vertices_num = polygon.size();
    // Step 2: Create the event queue and initialize it with vertex and edge events.
    std::vector<Coord> eventQueue = polygon;
    std::sort(eventQueue.begin(), eventQueue.end());

    // Step 3: Initialize the status data structure (e.g., a binary search tree).
    std::vector<Edge> newEdges;

    // Sweep line partitions boundaries
    std::set<Edge> activeEdges;

    // true if previous vertex was a merge vertex
    bool mergeFound = false;

    for (const Coord& event : eventQueue)
    {

        Coord prev = polygon[(event.index+vertices_num-1)%vertices_num];
        Coord next = polygon[(event.index+1)%vertices_num];

        // Determine whether this is a merge vertex, split vertex, or regular vertex.

        bool isMerge = false, isEnd = false, isSplit = false, isStart = false;
        if(prev.x < event.x && next.x < event.x)
        {
            if(prev.y > event.y)
                isMerge = true;
            else
                isEnd = true;
        }
        if(prev.x > event.x && next.x > event.x)
        {
            if(prev.y > event.y)
                isStart = true;
            else
                isSplit = true;
        }
        bool isRegularUpper = !isMerge && !isEnd && !isSplit && !isStart && next.x <= event.x && event.x <= prev.x;
        bool isRegularLower = !isMerge && !isEnd && !isSplit && !isStart && next.x >= event.x && event.x >= prev.x;

        if (isMerge) // Handle merge vertices 
        {
            std::cout << "Merge    " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(prev,event));
            activeEdges.erase(Edge(event,next));
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                    newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z, e->helper->index}}); 
            }
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(e)
                e->helper->x = event.x; e->helper->y = event.y; e->helper->z = event.z; e->helper->index = event.index;
            mergeFound = true;
        }
        if (isSplit) // Handle split vertices 
        {

            std::cout << "Split    " << event.x << "," << event.y << std::endl;

            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(e)
                newEdges.push_back({{event.x,event.y,event.z,event.index},{e->helper->x,e->helper->y,e->helper->z, e->helper->index}}); 
            
            activeEdges.insert(Edge(prev,event,event));
            activeEdges.insert(Edge(event,next,event));
            mergeFound = false;
        }
        if(isStart) 
        {
            std::cout << "Start    " << event.x << "," << event.y << std::endl;
            activeEdges.insert(Edge(prev,event,event));
            activeEdges.insert(Edge(next,event,event));
        }
        if(isEnd) 
        {
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                   newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            std::cout << "End      " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(prev,event));
            activeEdges.erase(Edge(event,next));
        }
        if (isRegularUpper) 
        {
            std::cout << "Upper    " << event.x << "," << event.y << std::endl;
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                   newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            activeEdges.erase(Edge(event,next));
            activeEdges.insert(Edge(event,prev,event));
        }
        if (isRegularLower) 
        {
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                    newEdges.push_back({{event.x,event.y,event.z,event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            std::cout << "Lower    " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(event,prev));
            activeEdges.insert(Edge(event,next,event));
        }
    }

    for(Edge e : newEdges)
    {
        std::cout << "Added edge: (" << e.start.x << ";" << e.start.y << ")   (" << e.end.x << ";" << e.end.y << ")\n";
    }
    return subdividePolygon(polygon,newEdges);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::vector<Triangle> getMesh()
{
  double height = 10;
  std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10}}; 
  polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {2,4}}; 
  //polygon = {{1,1},{3,4},{1,4},{2,2}}; 
  
  std::vector<Triangle> triangles;

  std::vector<double> intersections = std::vector<double>();

  for ( int i = polygon.size() - 1; i > 0; --i)
  {
    // generating 2 Triangles for the wall
    triangles.push_back(Triangle{ {polygon[i].x,polygon[i].y,0.0},
                                  {polygon[i].x,polygon[i].y,height},
                                  {polygon[i-1].x,polygon[i-1].y,height}});
    triangles.push_back(Triangle{ {polygon[i-1].x,polygon[i-1].y,0},
                                  {polygon[i-1].x,polygon[i-1].y,height},
                                  {polygon[i].x,polygon[i].y,0}});
  }


    // Stampa i triangoli
    
    for (auto p : partitionPolygonIntoMonotone(polygon))
    {
        std::cout << "Monotone polygon: ";
        for(auto v : p)
        {
            std::cout  <<"(" << v.x << ";" << v.y << ")  ";
        }
        std::cout << "\n";
    }


  return triangles;
}



int main(int argc, char* argv[])
{

  std::vector<Triangle> triangles = getMesh();

  Coord from = {9,0,6};
  Coord to = {9,12,0};

  //for(int i = 0; i < 1000000; i++)
  for (Triangle triangle : triangles)
  {
    double intersection = intersectmySegmentTriangle({to, from}, triangle);
    if (intersection == -1) {
        //std::cout << "Il mySegmento non interseca il triangolo." << std::endl;
    } else {
        std::cout << "Il mySegmento interseca il triangolo. Posizione: " << intersection << std::endl;
    }
  }

  return 0;
}