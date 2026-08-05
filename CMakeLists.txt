cmake_minimum_required(VERSION 3.16)
project(spark_recovered_model C)

add_library(spark_recovered_model STATIC
    src/recovered/pe_layout.c
    src/recovered/vm_entry.c
    src/recovered/vm_index.c
    src/recovered/import_surface.c
    src/recovered/dynamic_import_index.c
    src/recovered/dispatcher_model.c
)
target_include_directories(spark_recovered_model PUBLIC src/recovered)
target_compile_features(spark_recovered_model PRIVATE c_std_11)
