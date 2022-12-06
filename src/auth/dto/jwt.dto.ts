export class AtJwtPayload {
  public id: string;
  public login: string;
  public roles: string[];
  public iat: number;
  public exp: number;
}

export class RtJwtPayload {
  public id: string;
  public login: string;
  public iat: number;
  public exp: number;
}
