#include "irods/dataObjOpen.h"
#include "irods/procApiRequest.h"
#include "irods/apiNumber.h"

#include <cstring>

/**
 * \fn rcDataObjOpen (rcComm_t *conn, dataObjInp_t *dataObjInp)
 *
 * \brief Open a data object. This is equivalent to open of UNIX.
 *
 * \user client
 *
 * \ingroup data_object
 *
 * \since 1.0
 *
 *
 * \remark none
 *
 * \note none
 *
 * \usage
 * Open a data object /myZone/home/john/myfile in myRescource for write:
 * \n dataObjInp_t dataObjInp;
 * \n memset(&dataObjInp, 0, sizeof(dataObjInp));
 * \n rstrcpy (dataObjInp.objPath, "/myZone/home/john/myfile", MAX_NAME_LEN);
 * \n dataObjInp.openFlags = O_WRONLY;
 * \n addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, "myRescource");
 * \n status = rcDataObjOpen (conn, &dataObjInp);
 * \n if (status < 0) {
 * \n .... handle the error
 * \n }
 *
 * \param[in] conn - A rcComm_t connection handle to the server.
 * \param[in] dataObjInp - Elements of dataObjInp_t used :
 *    \li char \b objPath[MAX_NAME_LEN] - full path of the data object.
 *    \li int \b openFlags - the open flags. valid open flags are:
 *            O_RDONLY, O_WRONLY, O_RDWR and O_TRUNC.
 *    \li rodsLong_t \b dataSize - the size of the data object.
 *      Input 0 if not known.
 *    \li keyValPair_t \b condInput - keyword/value pair input. Valid keywords:
 *    \n DATA_TYPE_KW - the data type of the data object.
 *    \n RESC_NAME_KW - The resource of the data object to open.
 *    \n REPL_NUM_KW - the replica number of the copy to open.
 *
 * \return integer
 * \retval an opened object descriptor on success

 * \sideeffect none
 * \pre none
 * \post none
 * \sa none
**/

int
rcDataObjOpen( rcComm_t *conn, dataObjInp_t *dataObjInp ) {
    int status;
    status = procApiRequest( conn, DATA_OBJ_OPEN_AN,  dataObjInp, NULL,
                             ( void ** ) NULL, NULL );

    return status;
}

