#include <vector>
#include <utility>
#include <iostream>
#include <math.h>
#include <algorithm>
#include <set>
#include <list>
#include <map>

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

int arc_length(int i, int j, int N);

struct LessPredicate {
    int N; // Number of vertices in the polygon
    LessPredicate(int numVertices) : N(numVertices) {}

    bool operator()(const Edge& diag1, const Edge& diag2) const {
        int arcLenDiag1 = arc_length(diag1.start.index, diag1.end.index, N);
        int arcLenDiag2 = arc_length(diag2.start.index, diag2.end.index, N);
        return arcLenDiag1 < arcLenDiag2;
    }
};



/* tassellation.cpp */

std::vector<std::vector<Coord>> subdividePolygon(const std::vector<Coord>& perimeter, const std::vector<Edge>& diagonals);
const Edge* findUpperBound(double y,double x, std::set<Edge> bounds);
std::vector<std::vector<Coord>> partitionPolygonIntoMonotone(std::vector<Coord>& polygon);
std::vector<Triangle> tessellateMonotonePolygon(const std::vector<Coord>& polygon);

/* algebra.cpp */

Coord crossProduct(const Coord& v1, const Coord& v2);
double dotProduct(const Coord& v1, const Coord& v2);
double vectorLength(const Coord& vector);
double intersectmySegmentTriangle(const mySegment& mySegment, const Triangle& triangle);