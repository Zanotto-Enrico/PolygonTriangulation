#include <vector>
#include <utility>
#include <iostream>
#include <math.h>

/*                        ^
*                         |0
*                         |
*  10      * * * * * * * *|* * 
*          *              | *
*          *              | 
*          *            * |
*          *          *   |
*  5       *         *    |
*          *            * |
*          *              | *
*          *              |     *
*  1       * * * * * * * *|* * * * * 
*                         |
*                         |6 
*          1       5        10        15     
*/

struct Coord
{
  double x;
  double y;
  double z;
};



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
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




std::vector<Triangle> getMesh()
{
  double height = 10;
  std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10},{1,1}}; 

  
  std::vector<Triangle> triangles;

  std::vector<double> intersections = std::vector<double>();

  for ( int i = polygon.size() - 2; i > 1; --i)
  {
    // generating a floor Triangle
    triangles.push_back(Triangle{ {polygon[i].x,polygon[i].y,0},
                                  {polygon[i-1].x,polygon[i-1].y,0},
                                  {polygon[0].x,polygon[0].y,0}});
    // generating a roof Triangle
    triangles.push_back(Triangle{ {polygon[i].x,polygon[i].y,height},
                                  {polygon[i-1].x,polygon[i-1].y,height},
                                  {polygon[0].x,polygon[0].y,height}});
  }
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