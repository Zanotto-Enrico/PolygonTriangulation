#include "headers.hpp"

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