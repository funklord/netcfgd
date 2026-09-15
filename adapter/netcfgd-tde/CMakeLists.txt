#################################################
#
#  netcfgd's TDE front end: a control centre module
#  and a system tray monitor, both TQt3, both over
#  the same C client library the Qt window uses.
#
#################################################

include( TDEVersion )
cmake_minimum_required( VERSION ${TDE_CMAKE_MINIMUM_VERSION} )
tde_set_project_version( )
project( netcfgd-tde )

include( FindPkgConfig )
include( TDEMacros )
include( TDESetupPaths )
tde_setup_paths( )

find_package( TQt )
find_package( TDE )

tde_setup_architecture_flags( )
tde_setup_largefiles( )

# The C client library, which is what makes this cheap: nothing here
# reimplements the socket protocol.
set( NCFG_CLIENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../client"
     CACHE PATH "netcfgd's C client library sources" )

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${NCFG_CLIENT_DIR}
  ${TDE_INCLUDE_DIR}
  ${TQT_INCLUDE_DIRS}
)

link_directories(
  ${TQT_LIBRARY_DIRS}
  ${NCFG_CLIENT_DIR}
)

##### the control centre module #################

tde_add_kpart( kcm_netcfgd AUTOMOC
  SOURCES ncfg_tde_kcm.cpp ncfg_tde_connection.cpp
  LINK tdeui-shared tdecore-shared ncfg_client
  DESTINATION ${PLUGIN_INSTALL_DIR}
)

##### the tray monitor ##########################

tde_add_executable( netcfgd-tde-tray AUTOMOC
  SOURCES main.cpp ncfg_tde_tray.cpp ncfg_tde_connection.cpp
          ncfg_tde_tray.skel
  LINK tdeui-shared tdecore-shared ncfg_client
  DESTINATION ${BIN_INSTALL_DIR}
)

##### desktop files #############################

# The module goes where the control centre looks; the tray is an ordinary
# application entry.
install( FILES netcfgd.desktop DESTINATION ${XDG_APPS_INSTALL_DIR} )
install( FILES netcfgd-tde-tray.desktop DESTINATION ${XDG_APPS_INSTALL_DIR} )

# The autostart entry, conditional on netcfgdrc:General:Autostart. TDE reads
# that key at login and starts nothing when it is false, which is what lets
# the package ship the entry without deciding for the operator.
install( FILES netcfgd-tde-tray-autostart.desktop
         DESTINATION ${AUTOSTART_INSTALL_DIR} )
