#define CGAL_EIGEN3_ENABLED
#include <CGAL/Exact_predicates_exact_constructions_kernel.h>
#include <CGAL/poisson_surface_reconstruction.h>
#include <CGAL/intersections.h>
#include <CGAL/Surface_mesh/Surface_mesh.h>
#include <CGAL/Point_set_3/IO/XYZ.h>
#include <CGAL/Point_set_3.h>
#include <vector>
#include <utility>
#include <iostream>
#include <math.h>


typedef CGAL::Exact_predicates_exact_constructions_kernel K;
typedef K::Point_3 Point;
typedef K::Segment_3 Segment;
typedef K::Intersect_3 Intersect;
typedef K::Triangle_3 Triangle;
typedef CGAL::Point_set_3<Point> Point_set;
typedef CGAL::Surface_mesh<Point> Surface_mesh;

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




int CGAL_surface()
{
  Point_set points;
  CGAL::IO::read_XYZ("points.xyz", points);

  Surface_mesh output_mesh;
  CGAL::poisson_surface_reconstruction_delaunay(points.begin(), points.end(), points.point_map(), points.normal_map(), output_mesh, 10);

  //for(auto i : output_mesh.faces())
    //std::cout << i;


    /*PMP::triangulate_faces(output_mesh);
    //Confirm that all faces are triangles.
    for(boost::graph_traits<Surface_mesh>::face_descriptor f : faces(mesh))
      if(!CGAL::is_triangle(halfedge(f, mesh), mesh))
        std::cerr << "Error: non-triangular face left in mesh." << std::endl;
    CGAL::IO::write_polygon_mesh(outfilename, mesh, CGAL::parameters::stream_precision(17));
    */

  return 0;
}

int main(int argc, char* argv[])
{
  
  CGAL_surface();

  return 0;
}