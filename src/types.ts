export interface IUser {
  googleId?: string;
  facebookId?: string;
  githubId?: string;
  username: string;
}

export interface IMongoDBUser {
  googleId?: string;
  facebookId?: string;
  githubId?: string;
  username: string;
  __v: number;
  _id: string;
}
