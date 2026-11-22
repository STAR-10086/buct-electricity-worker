import rawCatalog from "./rooms.json";

export interface RawRoomItem {
  roomid: string;
  name: string;
  meterType?: string;
}

export interface RawFloorItem {
  floorid: string;
  name: string;
  rooms: RawRoomItem[];
}

export interface RawBuildingItem {
  buildingid: string;
  name: string;
  floors: RawFloorItem[];
}

export interface RawCampusItem {
  schoolid: string;
  name: string;
  hasMeterType: boolean;
  buildings: RawBuildingItem[];
}

export interface RawRoomsCatalog {
  factorycode: string;
  crawledAt: string;
  campuses: RawCampusItem[];
}

export interface RoomMeta {
  schoolid: string;
  campusName: string;
  buildingid: string;
  buildingName: string;
  floorid: string;
  floorName: string;
  roomid: string;
  roomName: string;
  meterType: string;
}

const catalog = rawCatalog as RawRoomsCatalog;

export const ROOMS_JSON_STRING = JSON.stringify(catalog);

const roomIndex = new Map<string, RoomMeta>();

for (const campus of catalog.campuses) {
  for (const building of campus.buildings) {
    for (const floor of building.floors) {
      for (const room of floor.rooms) {
        roomIndex.set(`${campus.schoolid}\u0000${room.roomid}`, {
          schoolid: campus.schoolid,
          campusName: campus.name,
          buildingid: building.buildingid,
          buildingName: building.name,
          floorid: floor.floorid,
          floorName: floor.name,
          roomid: room.roomid,
          roomName: room.name,
          meterType: room.meterType ?? "",
        });
      }
    }
  }
}

export const TOTAL_ROOMS = roomIndex.size;

/**
 * O(1) whitelist lookup for (schoolid, roomid).
 */
export function lookupRoom(schoolid: string, roomid: string): RoomMeta | undefined {
  return roomIndex.get(`${schoolid}\u0000${roomid}`);
}
